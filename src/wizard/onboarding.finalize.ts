import fs from "node:fs/promises";
import path from "node:path";
import { DEFAULT_BOOTSTRAP_FILENAME } from "../agents/workspace.js";
import { formatCliCommand } from "../cli/command-format.js";
import {
  buildGatewayInstallPlan,
  gatewayInstallErrorHint,
} from "../commands/daemon-install-helpers.js";
import {
  DEFAULT_GATEWAY_DAEMON_RUNTIME,
  GATEWAY_DAEMON_RUNTIME_OPTIONS,
} from "../commands/daemon-runtime.js";
import { resolveGatewayInstallToken } from "../commands/gateway-install-token.js";
import { formatHealthCheckFailure } from "../commands/health-format.js";
import { healthCommand } from "../commands/health.js";
import {
  detectBrowserOpenSupport,
  formatControlUiSshHint,
  openUrl,
  probeGatewayReachable,
  waitForGatewayReachable,
  resolveControlUiLinks,
} from "../commands/onboard-helpers.js";
import type { OnboardOptions } from "../commands/onboard-types.js";
import type { OpenClawConfig } from "../config/config.js";
import { resolveGatewayService } from "../daemon/service.js";
import { isSystemdUserServiceAvailable } from "../daemon/systemd.js";
import { ensureControlUiAssetsBuilt } from "../infra/control-ui-assets.js";
import type { RuntimeEnv } from "../runtime.js";
import { restoreTerminalState } from "../terminal/restore.js";
import { runTui } from "../tui/tui.js";
import { resolveUserPath } from "../utils.js";
import { setupOnboardingShellCompletion } from "./onboarding.completion.js";
import { resolveOnboardingSecretInputString } from "./onboarding.secret-input.js";
import type { GatewayWizardSettings, WizardFlow } from "./onboarding.types.js";
import type { WizardPrompter } from "./prompts.js";

type FinalizeOnboardingOptions = {
  flow: WizardFlow;
  opts: OnboardOptions;
  baseConfig: OpenClawConfig;
  nextConfig: OpenClawConfig;
  workspaceDir: string;
  settings: GatewayWizardSettings;
  prompter: WizardPrompter;
  runtime: RuntimeEnv;
};

export async function finalizeOnboardingWizard(
  options: FinalizeOnboardingOptions,
): Promise<{ launchedTui: boolean }> {
  const { flow, opts, baseConfig, nextConfig, settings, prompter, runtime } = options;

  const withWizardProgress = async <T>(
    label: string,
    options: { doneMessage?: string },
    work: (progress: { update: (message: string) => void }) => Promise<T>,
  ): Promise<T> => {
    const progress = prompter.progress(label);
    try {
      return await work(progress);
    } finally {
      progress.stop(options.doneMessage);
    }
  };

  const systemdAvailable =
    process.platform === "linux" ? await isSystemdUserServiceAvailable() : true;
  if (process.platform === "linux" && !systemdAvailable) {
    await prompter.note(
      "Systemd 用户服务不可用。跳过驻留检查和服务安装。",
      "Systemd",
    );
  }

  if (process.platform === "linux" && systemdAvailable) {
    const { ensureSystemdUserLingerInteractive } = await import("../commands/systemd-linger.js");
    await ensureSystemdUserLingerInteractive({
      runtime,
      prompter: {
        confirm: prompter.confirm,
        note: prompter.note,
      },
      reason:
        "Linux 安装默认使用 systemd 用户服务。如果不启用驻留 (lingering)，systemd 会在注销/闲置时停止用户会话并终止网关。",
      requireConfirm: false,
    });
  }

  const explicitInstallDaemon =
    typeof opts.installDaemon === "boolean" ? opts.installDaemon : undefined;
  let installDaemon: boolean;
  if (explicitInstallDaemon !== undefined) {
    installDaemon = explicitInstallDaemon;
  } else if (process.platform === "linux" && !systemdAvailable) {
    installDaemon = false;
  } else if (flow === "quickstart") {
    installDaemon = true;
  } else {
    installDaemon = await prompter.confirm({
      message: "安装网关服务（推荐）",
      initialValue: true,
    });
  }

  if (process.platform === "linux" && !systemdAvailable && installDaemon) {
    await prompter.note(
      "Systemd 用户服务不可用；跳过服务安装。请使用您的容器管理器或 `docker compose up -d`。",
      "网关服务",
    );
    installDaemon = false;
  }

  if (installDaemon) {
    const daemonRuntime =
      flow === "quickstart"
        ? DEFAULT_GATEWAY_DAEMON_RUNTIME
        : await prompter.select({
            message: "网关服务运行时",
            options: GATEWAY_DAEMON_RUNTIME_OPTIONS,
            initialValue: opts.daemonRuntime ?? DEFAULT_GATEWAY_DAEMON_RUNTIME,
          });
    if (flow === "quickstart") {
      await prompter.note(
        "快速开始使用 Node 运行网关服务（稳定且受支持）。",
        "网关服务运行时",
      );
    }
    const service = resolveGatewayService();
    const loaded = await service.isLoaded({ env: process.env });
    if (loaded) {
      const action = await prompter.select({
        message: "网关服务已安装",
        options: [
          { value: "restart", label: "重启" },
          { value: "reinstall", label: "重新安装" },
          { value: "skip", label: "跳过" },
        ],
      });
      if (action === "restart") {
        await withWizardProgress(
          "网关服务",
          { doneMessage: "网关服务已重启。" },
          async (progress) => {
            progress.update("正在重启网关服务…");
            await service.restart({
              env: process.env,
              stdout: process.stdout,
            });
          },
        );
      } else if (action === "reinstall") {
        await withWizardProgress(
          "网关服务",
          { doneMessage: "网关服务已卸载。" },
          async (progress) => {
            progress.update("正在卸载网关服务…");
            await service.uninstall({ env: process.env, stdout: process.stdout });
          },
        );
      }
    }

    if (!loaded || (loaded && !(await service.isLoaded({ env: process.env })))) {
      const progress = prompter.progress("网关服务");
      let installError: string | null = null;
      try {
        progress.update("正在准备网关服务…");
        const tokenResolution = await resolveGatewayInstallToken({
          config: nextConfig,
          env: process.env,
        });
        for (const warning of tokenResolution.warnings) {
          await prompter.note(warning, "网关服务");
        }
        if (tokenResolution.unavailableReason) {
          installError = [
            "网关安装被阻止：",
            tokenResolution.unavailableReason,
            "修复网关认证配置/令牌输入，然后重新运行配置向导。",
          ].join(" ");
        } else {
          const { programArguments, workingDirectory, environment } = await buildGatewayInstallPlan(
            {
              env: process.env,
              port: settings.port,
              token: tokenResolution.token,
              runtime: daemonRuntime,
              warn: (message, title) => prompter.note(message, title),
              config: nextConfig,
            },
          );

          progress.update("正在安装网关服务…");
          await service.install({
            env: process.env,
            stdout: process.stdout,
            programArguments,
            workingDirectory,
            environment,
          });
        }
      } catch (err) {
        installError = err instanceof Error ? err.message : String(err);
      } finally {
        progress.stop(
          installError ? "网关服务安装失败。" : "网关服务安装成功。",
        );
      }
      if (installError) {
        await prompter.note(`网关服务安装失败：${installError}`, "网关");
        await prompter.note(gatewayInstallErrorHint(), "网关");
      }
    }
  }

  if (!opts.skipHealth) {
    const probeLinks = resolveControlUiLinks({
      bind: nextConfig.gateway?.bind ?? "loopback",
      port: settings.port,
      customBindHost: nextConfig.gateway?.customBindHost,
      basePath: undefined,
    });
    // Daemon install/restart can briefly flap the WS; wait a bit so health check doesn't false-fail.
    await waitForGatewayReachable({
      url: probeLinks.wsUrl,
      token: settings.gatewayToken,
      deadlineMs: 15_000,
    });
    try {
      await healthCommand({ json: false, timeoutMs: 10_000 }, runtime);
    } catch (err) {
      runtime.error(formatHealthCheckFailure(err));
      await prompter.note(
        [
          "文档:",
          "https://docs.openclaw.ai/gateway/health",
          "https://docs.openclaw.ai/gateway/troubleshooting",
        ].join("\n"),
        "健康检查帮助",
      );
    }
  }

  const controlUiEnabled =
    nextConfig.gateway?.controlUi?.enabled ?? baseConfig.gateway?.controlUi?.enabled ?? true;
  if (!opts.skipUi && controlUiEnabled) {
    const controlUiAssets = await ensureControlUiAssetsBuilt(runtime);
    if (!controlUiAssets.ok && controlUiAssets.message) {
      runtime.error(controlUiAssets.message);
    }
  }

  await prompter.note(
    [
      "Add nodes for extra features:",
      "- macOS app (system + notifications)",
      "- iOS app (camera/canvas)",
      "- Android app (camera/canvas)",
    ].join("\n"),
    "Optional apps",
  );

  const controlUiBasePath =
    nextConfig.gateway?.controlUi?.basePath ?? baseConfig.gateway?.controlUi?.basePath;
  const links = resolveControlUiLinks({
    bind: settings.bind,
    port: settings.port,
    customBindHost: settings.customBindHost,
    basePath: controlUiBasePath,
  });
  const authedUrl =
    settings.authMode === "token" && settings.gatewayToken
      ? `${links.httpUrl}#token=${encodeURIComponent(settings.gatewayToken)}`
      : links.httpUrl;
  let resolvedGatewayPassword = "";
  if (settings.authMode === "password") {
    try {
      resolvedGatewayPassword =
        (await resolveOnboardingSecretInputString({
          config: nextConfig,
          value: nextConfig.gateway?.auth?.password,
          path: "gateway.auth.password",
          env: process.env,
        })) ?? "";
    } catch (error) {
      await prompter.note(
        [
          "Could not resolve gateway.auth.password SecretRef for onboarding auth.",
          error instanceof Error ? error.message : String(error),
        ].join("\n"),
        "Gateway auth",
      );
    }
  }

  const gatewayProbe = await probeGatewayReachable({
    url: links.wsUrl,
    token: settings.authMode === "token" ? settings.gatewayToken : undefined,
    password: settings.authMode === "password" ? resolvedGatewayPassword : "",
  });
  const gatewayStatusLine = gatewayProbe.ok
    ? "Gateway: reachable"
    : `Gateway: not detected${gatewayProbe.detail ? ` (${gatewayProbe.detail})` : ""}`;
  const bootstrapPath = path.join(
    resolveUserPath(options.workspaceDir),
    DEFAULT_BOOTSTRAP_FILENAME,
  );
  const hasBootstrap = await fs
    .access(bootstrapPath)
    .then(() => true)
    .catch(() => false);

  await prompter.note(
    [
      `Web UI: ${links.httpUrl}`,
      settings.authMode === "token" && settings.gatewayToken
        ? `Web UI (with token): ${authedUrl}`
        : undefined,
      `Gateway WS: ${links.wsUrl}`,
      gatewayStatusLine,
      "Docs: https://docs.openclaw.ai/web/control-ui",
    ]
      .filter(Boolean)
      .join("\n"),
    "Control UI",
  );

  let controlUiOpened = false;
  let controlUiOpenHint: string | undefined;
  let seededInBackground = false;
  let hatchChoice: "tui" | "web" | "later" | null = null;
  let launchedTui = false;

  if (!opts.skipUi && gatewayProbe.ok) {
    if (hasBootstrap) {
      await prompter.note(
        [
          "This is the defining action that makes your agent you.",
          "Please take your time.",
          "The more you tell it, the better the experience will be.",
          'We will send: "Wake up, my friend!"',
        ].join("\n"),
        "Start TUI (best option!)",
      );
    }

    await prompter.note(
      [
        "Gateway token: shared auth for the Gateway + Control UI.",
        "Stored in: ~/.openclaw/openclaw.json (gateway.auth.token) or OPENCLAW_GATEWAY_TOKEN.",
        `View token: ${formatCliCommand("openclaw config get gateway.auth.token")}`,
        `Generate token: ${formatCliCommand("openclaw doctor --generate-gateway-token")}`,
        "Web UI stores a copy in this browser's localStorage (openclaw.control.settings.v1).",
        `Open the dashboard anytime: ${formatCliCommand("openclaw dashboard --no-open")}`,
        "If prompted: paste the token into Control UI settings (or use the tokenized dashboard URL).",
      ].join("\n"),
      "Token",
    );

    hatchChoice = await prompter.select({
      message: "How do you want to hatch your bot?",
      options: [
        { value: "tui", label: "Hatch in TUI (recommended)" },
        { value: "web", label: "Open the Web UI" },
        { value: "later", label: "Do this later" },
      ],
      initialValue: "tui",
    });

    if (hatchChoice === "tui") {
      restoreTerminalState("pre-onboarding tui", { resumeStdinIfPaused: true });
      await runTui({
        url: links.wsUrl,
        token: settings.authMode === "token" ? settings.gatewayToken : undefined,
        password: settings.authMode === "password" ? resolvedGatewayPassword : "",
        // Safety: onboarding TUI should not auto-deliver to lastProvider/lastTo.
        deliver: false,
        message: hasBootstrap ? "Wake up, my friend!" : undefined,
      });
      launchedTui = true;
    } else if (hatchChoice === "web") {
      const browserSupport = await detectBrowserOpenSupport();
      if (browserSupport.ok) {
        controlUiOpened = await openUrl(authedUrl);
        if (!controlUiOpened) {
          controlUiOpenHint = formatControlUiSshHint({
            port: settings.port,
            basePath: controlUiBasePath,
            token: settings.authMode === "token" ? settings.gatewayToken : undefined,
          });
        }
      } else {
        controlUiOpenHint = formatControlUiSshHint({
          port: settings.port,
          basePath: controlUiBasePath,
          token: settings.authMode === "token" ? settings.gatewayToken : undefined,
        });
      }
      await prompter.note(
        [
          `Dashboard link (with token): ${authedUrl}`,
          controlUiOpened
            ? "Opened in your browser. Keep that tab to control OpenClaw."
            : "Copy/paste this URL in a browser on this machine to control OpenClaw.",
          controlUiOpenHint,
        ]
          .filter(Boolean)
          .join("\n"),
        "Dashboard ready",
      );
    } else {
      await prompter.note(
        `When you're ready: ${formatCliCommand("openclaw dashboard --no-open")}`,
        "Later",
      );
    }
  } else if (opts.skipUi) {
    await prompter.note("Skipping Control UI/TUI prompts.", "Control UI");
  }

  await prompter.note(
    [
      "Back up your agent workspace.",
      "Docs: https://docs.openclaw.ai/concepts/agent-workspace",
    ].join("\n"),
    "Workspace backup",
  );

  await prompter.note(
    "Running agents on your computer is risky — harden your setup: https://docs.openclaw.ai/security",
    "Security",
  );

  await setupOnboardingShellCompletion({ flow, prompter });

  const shouldOpenControlUi =
    !opts.skipUi &&
    settings.authMode === "token" &&
    Boolean(settings.gatewayToken) &&
    hatchChoice === null;
  if (shouldOpenControlUi) {
    const browserSupport = await detectBrowserOpenSupport();
    if (browserSupport.ok) {
      controlUiOpened = await openUrl(authedUrl);
      if (!controlUiOpened) {
        controlUiOpenHint = formatControlUiSshHint({
          port: settings.port,
          basePath: controlUiBasePath,
          token: settings.gatewayToken,
        });
      }
    } else {
      controlUiOpenHint = formatControlUiSshHint({
        port: settings.port,
        basePath: controlUiBasePath,
        token: settings.gatewayToken,
      });
    }

    await prompter.note(
      [
        `Dashboard link (with token): ${authedUrl}`,
        controlUiOpened
          ? "Opened in your browser. Keep that tab to control OpenClaw."
          : "Copy/paste this URL in a browser on this machine to control OpenClaw.",
        controlUiOpenHint,
      ]
        .filter(Boolean)
        .join("\n"),
      "Dashboard ready",
    );
  }

  const webSearchProvider = nextConfig.tools?.web?.search?.provider;
  const webSearchEnabled = nextConfig.tools?.web?.search?.enabled;
  if (webSearchProvider) {
    const { SEARCH_PROVIDER_OPTIONS, resolveExistingKey, hasExistingKey, hasKeyInEnv } =
      await import("../commands/onboard-search.js");
    const entry = SEARCH_PROVIDER_OPTIONS.find((e) => e.value === webSearchProvider);
    const label = entry?.label ?? webSearchProvider;
    const storedKey = resolveExistingKey(nextConfig, webSearchProvider);
    const keyConfigured = hasExistingKey(nextConfig, webSearchProvider);
    const envAvailable = entry ? hasKeyInEnv(entry) : false;
    const hasKey = keyConfigured || envAvailable;
    const keySource = storedKey
      ? "API key: stored in config."
      : keyConfigured
        ? "API key: configured via secret reference."
        : envAvailable
          ? `API key: provided via ${entry?.envKeys.join(" / ")} env var.`
          : undefined;
    if (webSearchEnabled !== false && hasKey) {
      await prompter.note(
        [
          "Web search is enabled, so your agent can look things up online when needed.",
          "",
          `Provider: ${label}`,
          ...(keySource ? [keySource] : []),
          "Docs: https://docs.openclaw.ai/tools/web",
        ].join("\n"),
        "Web search",
      );
    } else if (!hasKey) {
      await prompter.note(
        [
          `Provider ${label} is selected but no API key was found.`,
          "web_search will not work until a key is added.",
          `  ${formatCliCommand("openclaw configure --section web")}`,
          "",
          `Get your key at: ${entry?.signupUrl ?? "https://docs.openclaw.ai/tools/web"}`,
          "Docs: https://docs.openclaw.ai/tools/web",
        ].join("\n"),
        "Web search",
      );
    } else {
      await prompter.note(
        [
          `Web search (${label}) is configured but disabled.`,
          `Re-enable: ${formatCliCommand("openclaw configure --section web")}`,
          "",
          "Docs: https://docs.openclaw.ai/tools/web",
        ].join("\n"),
        "Web search",
      );
    }
  } else {
    // Legacy configs may have a working key (e.g. apiKey or BRAVE_API_KEY) without
    // an explicit provider. Runtime auto-detects these, so avoid saying "skipped".
    const { SEARCH_PROVIDER_OPTIONS, hasExistingKey, hasKeyInEnv } =
      await import("../commands/onboard-search.js");
    const legacyDetected = SEARCH_PROVIDER_OPTIONS.find(
      (e) => hasExistingKey(nextConfig, e.value) || hasKeyInEnv(e),
    );
    if (legacyDetected) {
      await prompter.note(
        [
          `Web search is available via ${legacyDetected.label} (auto-detected).`,
          "Docs: https://docs.openclaw.ai/tools/web",
        ].join("\n"),
        "Web search",
      );
    } else {
      await prompter.note(
        [
          "Web search was skipped. You can enable it later:",
          `  ${formatCliCommand("openclaw configure --section web")}`,
          "",
          "Docs: https://docs.openclaw.ai/tools/web",
        ].join("\n"),
        "Web search",
      );
    }
  }

  await prompter.note(
    'What now: https://openclaw.ai/showcase ("What People Are Building").',
    "What now",
  );

  await prompter.outro(
    controlUiOpened
      ? "Onboarding complete. Dashboard opened; keep that tab to control OpenClaw."
      : seededInBackground
        ? "Onboarding complete. Web UI seeded in the background; open it anytime with the dashboard link above."
        : "Onboarding complete. Use the dashboard link above to control OpenClaw.",
  );

  return { launchedTui };
}
