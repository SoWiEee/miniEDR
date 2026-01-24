#include "collectors/sysmon_collector.h"
#include "collectors/etw_kernel_collector.h"

#include "pipeline/normalizer.h"
#include "detection/rule_engine.h"
#include "detection/correlator.h"
#include "output/alert_sinks.h"

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

    auto EmitFindings = [&](const std::vector<Finding>& findings) {
        for (const auto& f : findings) {
            for (auto& s : sinks) s->Emit(f);
        }
    };

    auto HandleEvent = [&](const CanonicalEvent& ev) {
        EmitFindings(engine.Evaluate(ev));
        EmitFindings(correlator.Process(ev));
    };

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
    if (!no_etw) {
        etw = std::make_unique<EtwKernelCollector>();
        etw->Start([&](const CanonicalEvent& ev) {
            HandleEvent(ev);
        });
    } else {
        std::wcout << L"[Main] ETW disabled.\n";
    }

    while (g_running) {
        Sleep(200);
    }

    if (sysmon) sysmon->Stop();
    if (etw) etw->Stop();

    std::wcout << L"\nStopping.\n";
    return 0;
#endif
}
