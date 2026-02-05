#include "collectors/sysmon_collector.h"
#include "collectors/etw_kernel_collector.h"
#include "collectors/etw_user_collector.h"
#include "collectors/driver_collector.h"
#include "collectors/api_hook_collector.h"

#include "pipeline/normalizer.h"
#include "detection/rule_engine.h"
#include "detection/correlator.h"
#include "output/alert_sinks.h"
#include "output/central_sink.h"
#include "scanners/scanner_manager.h"
#include "response/response_manager.h"
#include "control/central_config.h"
#include "control/central_manager.h"

#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace miniedr;

static std::atomic<bool> g_running{true};

static void OnSignal(int) {
    g_running = false;
}

static bool HasArg(int argc, wchar_t** argv, const wchar_t* flag) {
    for (int i = 1; i < argc; i++) {
        if (_wcsicmp(argv[i], flag) == 0) return true;
    }
    return false;
}

int wmain(int argc, wchar_t** argv) {
    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);

#ifndef _WIN32
    std::wcerr << L"This build currently targets Windows only.\n";
    return 1;
#else
    const bool no_sysmon = HasArg(argc, argv, L"--no-sysmon");
    const bool no_etw = HasArg(argc, argv, L"--no-etw");

    std::wcout << L"MiniEDR Phase 2 - Sysmon + ETW -> Normalize -> Rules + Correlation -> Alerts\n";
    std::wcout << L"Flags: --no-sysmon, --no-etw\n";
    std::wcout << L"Press Ctrl+C to stop.\n\n";

    Normalizer normalizer;
    RuleEngine engine;
    Correlator correlator;

    std::vector<std::unique_ptr<IAlertSink>> sinks;
    sinks.emplace_back(std::make_unique<ConsoleSink>());
    sinks.emplace_back(std::make_unique<JsonlFileSink>(L"alerts.jsonl"));

    // Phase 3: on-demand deep scans for high-severity findings
    auto scan_cfg = LoadScannerConfig(L"agent\\config\\scanners.json");
    ScannerManager scanner_mgr(scan_cfg);

    // Phase 3: response actions (disabled by default)
    ResponseConfig resp_cfg;
    resp_cfg.enable_response = false;
    resp_cfg.auto_terminate_on_critical = false;
#ifdef _WIN32
    resp_cfg.hooking = LoadHookingConfig(L"agent\\config\\hooking.json");
#endif
    CentralConfig central_cfg = LoadCentralConfig(L"agent\\config\\central_config.json");
    CentralManager central_mgr(central_cfg);
    if (central_cfg.enable) {
        auto policy = central_mgr.LoadPolicyFromFile(L"agent\\config\\policy.json");
        central_mgr.ApplyPolicy(resp_cfg, policy);
    }
    ResponseManager resp_mgr(resp_cfg);

    if (central_cfg.enable && central_cfg.upload_events) {
        sinks.emplace_back(std::make_unique<CentralUploadSink>(central_mgr));
    }

    auto EmitFindings = [&](const std::vector<Finding>& findings) {
    for (const auto& f : findings) {
        EnrichedFinding ef;
        ef.rule_id = f.rule_id;
        ef.title = f.title;
        ef.severity = f.severity;
        ef.summary = f.summary;
        ef.evidence = f.evidence;

        ef.scans = scanner_mgr.RunOnDemand(f);

        for (auto& s : sinks) s->EmitEnriched(ef);

            (void)resp_mgr.Handle(ef);
    }
};

    auto HandleEvent = [&](const CanonicalEvent& ev) {
        EmitFindings(engine.Evaluate(ev));
        EmitFindings(correlator.Process(ev));
    };

    if (central_cfg.enable) {
        central_mgr.Start();
    }

    std::unique_ptr<SysmonCollector> sysmon;
    if (!no_sysmon) {
        sysmon = std::make_unique<SysmonCollector>();
        if (!sysmon->Start([&](uint32_t eid, const std::wstring& xml) {
            auto ev_opt = normalizer.NormalizeSysmonXml(eid, xml);
            if (!ev_opt) return;
            HandleEvent(*ev_opt);
        })) {
            std::wcerr << L"Sysmon collector failed to start.\n";
            return 2;
        }
    } else {
        std::wcout << L"[Main] Sysmon disabled.\n";
    }

    std::unique_ptr<EtwKernelCollector> etw;
    std::unique_ptr<EtwUserCollector> etw_user;
    if (!no_etw) {
        etw = std::make_unique<EtwKernelCollector>();
        etw->Start([&](const CanonicalEvent& ev) {
            HandleEvent(ev);
        });
        etw_user = std::make_unique<EtwUserCollector>();
        etw_user->Start([&](const CanonicalEvent& ev) {
            HandleEvent(ev);
        });
    } else {
        std::wcout << L"[Main] ETW disabled.\n";
    }
    std::unique_ptr<DriverCollector> kmdf;
    // Phase 4: optional KMDF kernel driver telemetry via IOCTL (\\.\MiniEDRDrv)
    // If the driver is not installed/running, this collector will fail open and the agent continues.
    kmdf = std::make_unique<DriverCollector>();
    if (!kmdf->Start([&](const CanonicalEvent& ev) { HandleEvent(ev); })) {
        std::wcout << L"[Main] KMDF driver collector not available.\n";
        kmdf.reset();
    } else {
        std::wcout << L"[Main] KMDF driver collector enabled.\n";
    }

    
    std::unique_ptr<ApiHookCollector> apihook;
#ifdef _WIN32
    if (resp_cfg.hooking.enable_hooking) {
        apihook = std::make_unique<ApiHookCollector>();
        apihook->Start([&](const CanonicalEvent& ev) { HandleEvent(ev); });
        std::wcout << L"[Main] ApiHook collector enabled (named pipe).\n";
    } else {
        std::wcout << L"[Main] ApiHook collector disabled.\n";
    }
#endif

    while (g_running) {
        Sleep(200);
    }

    if (apihook) apihook->Stop();
    if (sysmon) sysmon->Stop();
    if (etw_user) etw_user->Stop();
    if (etw) etw->Stop();
    central_mgr.Stop();

    std::wcout << L"\nStopping.\n";
    return 0;
#endif
}
