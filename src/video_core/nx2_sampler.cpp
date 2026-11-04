// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#include "video_core/nx2_sampler.h"

#ifdef _WIN32

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <fmt/format.h>

#include "common/common_types.h"
#include "common/fs/fs_paths.h"
#include "common/fs/path_util.h"
#include "common/logging.h"

namespace VideoCommon::Nx2Sampler {
namespace {

constexpr size_t MaxDepth = 32;
constexpr size_t MaxThreads = 4;

struct Target {
    HANDLE handle{};
    std::string name;
    u64 samples{};
    /// Stacks (innermost first) and how often each was seen.
    std::map<std::vector<u64>, u64> stacks;
};

struct State {
    std::mutex mutex; ///< Guards targets against registration; never held while one is suspended
    std::array<Target, MaxThreads> targets;
    std::atomic<size_t> count{};
    std::jthread thread;
};

State& Get() {
    static State state;
    return state;
}

bool Enabled() {
    static const bool enabled = [] {
        const char* value = std::getenv("EDEN_NX2_SAMPLE");
        return value != nullptr && value[0] == '1';
    }();
    return enabled;
}

// Walks the suspended thread's stack from its context. Only reads its memory and the unwind
// tables; allocates nothing (the thread may hold the heap lock).
size_t Walk(CONTEXT context, std::array<u64, MaxDepth>& frames) {
    size_t depth = 0;
    while (depth < MaxDepth && context.Rip != 0) {
        frames[depth++] = context.Rip;
        DWORD64 image_base{};
        const PRUNTIME_FUNCTION function = RtlLookupFunctionEntry(context.Rip, &image_base, nullptr);
        if (function == nullptr) {
            // A leaf function: the return address is at the top of the stack.
            if (context.Rsp == 0) {
                break;
            }
            context.Rip = *reinterpret_cast<const DWORD64*>(context.Rsp);
            context.Rsp += 8;
            continue;
        }
        PVOID handler_data{};
        DWORD64 establisher_frame{};
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, image_base, context.Rip, function, &context,
                         &handler_data, &establisher_frame, nullptr);
    }
    return depth;
}

std::string Describe(u64 address, std::unordered_map<u64, std::string>& modules) {
    HMODULE module{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &module)) {
        return fmt::format("?+{:x}", address);
    }
    const u64 base = reinterpret_cast<u64>(module);
    auto [it, inserted] = modules.try_emplace(base);
    if (inserted) {
        std::array<char, MAX_PATH> path{};
        const DWORD length = GetModuleFileNameA(module, path.data(), static_cast<DWORD>(path.size()));
        std::string name{path.data(), length};
        if (const size_t slash = name.find_last_of("\\/"); slash != std::string::npos) {
            name = name.substr(slash + 1);
        }
        it->second = name;
    }
    return fmt::format("{}+{:x}", it->second, address - base);
}

void Write(State& state) {
    using namespace Common::FS;
    const auto path = GetEdenPath(EdenPath::LogDir) / "nx2_samples.txt";
    std::FILE* file = _wfopen(path.c_str(), L"w");
    if (file == nullptr) {
        return;
    }
    std::unordered_map<u64, std::string> modules;
    for (size_t i = 0; i < state.count.load(); ++i) {
        const Target& target = state.targets[i];
        std::fprintf(file, "thread %s: %llu samples\n", target.name.c_str(),
                     static_cast<unsigned long long>(target.samples));
        // Most frequent first.
        std::vector<std::pair<u64, const std::vector<u64>*>> order;
        order.reserve(target.stacks.size());
        for (const auto& [stack, seen] : target.stacks) {
            order.emplace_back(seen, &stack);
        }
        std::sort(order.begin(), order.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });
        for (const auto& [seen, stack] : order) {
            std::string line = fmt::format("{}", seen);
            for (const u64 address : *stack) {
                line += ' ';
                line += Describe(address, modules);
            }
            std::fprintf(file, "%s\n", line.c_str());
        }
    }
    std::fclose(file);
}

void Run(std::stop_token stop_token) {
    State& state = Get();
    auto next_write = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    std::array<u64, MaxDepth> frames{};
    std::vector<u64> stack;
    while (!stop_token.stop_requested()) {
        Sleep(1);
        const size_t count = state.count.load();
        for (size_t i = 0; i < count; ++i) {
            Target& target = state.targets[i];
            if (SuspendThread(target.handle) == static_cast<DWORD>(-1)) {
                continue;
            }
            CONTEXT context{};
            context.ContextFlags = CONTEXT_FULL;
            size_t depth = 0;
            if (GetThreadContext(target.handle, &context)) {
                depth = Walk(context, frames);
            }
            ResumeThread(target.handle);
            if (depth == 0) {
                continue;
            }
            stack.assign(frames.begin(), frames.begin() + depth);
            ++target.stacks[stack];
            ++target.samples;
        }
        if (std::chrono::steady_clock::now() >= next_write) {
            next_write += std::chrono::seconds{10};
            Write(state);
            LOG_INFO(HW_GPU, "Sampler: stacks written to nx2_samples.txt");
        }
    }
}

} // Anonymous namespace

void RegisterCurrentThread(const char* name) {
    if (!Enabled()) {
        return;
    }
    State& state = Get();
    std::scoped_lock lock{state.mutex};
    const size_t index = state.count.load();
    if (index >= MaxThreads) {
        return;
    }
    HANDLE handle{};
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &handle,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                         FALSE, 0)) {
        return;
    }
    state.targets[index].handle = handle;
    state.targets[index].name = name;
    state.count.store(index + 1);
    if (!state.thread.joinable()) {
        state.thread = std::jthread{Run};
    }
    LOG_INFO(HW_GPU, "Sampler: sampling thread {}", name);
}

} // namespace VideoCommon::Nx2Sampler

#else

namespace VideoCommon::Nx2Sampler {
void RegisterCurrentThread(const char*) {}
} // namespace VideoCommon::Nx2Sampler

#endif
