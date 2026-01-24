#include "collectors/sysmon_collector.h"
#include "pipeline/normalizer.h"
#include "detection/rule_engine.h"
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

int wmain(int argc, wchar_t** argv) {
    (void)argc; (void)argv;

    std::signal(SIGINT, OnSignal);
    std::signal(SIGTERM, OnSignal);

    std::wcout << L"MiniEDR Phase 1 - Sysmon(ProcessCreate) -> Rules -> Alerts\n";
    std::wcout << L"Press Ctrl+C to stop.\n\n";

#ifndef _WIN32
    std::wcerr << L"This build currently targets Windows only.\n";
    return 1;
#else
    Normalizer normalizer;
    RuleEngine engine;

    std::vector<std::unique_ptr<IAlertSink>> sinks;
    sinks.emplace_back(std::make_unique<ConsoleSink>());
    sinks.emplace_back(std::make_unique<JsonlFileSink>(L"alerts.jsonl"));

    SysmonCollector collector;
    if (!collector.Start([&](uint32_t eid, const std::wstring& xml) {
        auto ev_opt = normalizer.NormalizeSysmonXml(eid, xml);
        if (!ev_opt) return;

        auto findings = engine.Evaluate(*ev_opt);
        for (const auto& f : findings) {
            for (auto& s : sinks) s->Emit(f);
        }
    })) {
        return 2;
    }

    while (g_running) {
        Sleep(200);
    }

    collector.Stop();
    std::wcout << L"\nStopping.\n";
    return 0;
#endif
}
