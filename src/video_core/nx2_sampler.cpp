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
constexpr size_t MaxThreads = 8;

struct Target {
    HANDLE handle{};
    std::string name;
    u64 samples{};
    /// Stacks (innermost first) and how often each was seen: all, and since the last write.
    std::map<std::vector<u64>, u64> stacks;
    std::map<std::vector<u64>, u64> window_stacks;
    u64 window_samples{};
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

// Code mapped from a module (MEM_IMAGE): its unwind tables are static. Other code (the CPU
// JIT's) is not unwound: looking its tables up could wait on a lock the suspended thread holds.
// Asks the kernel (VirtualQuery takes no user-mode lock), remembering the image ranges found.
bool InImage(u64 address) {
    struct Range {
        u64 begin;
        u64 end;
    };
    static std::array<Range, 128> ranges{};
    static size_t count = 0;
    for (size_t i = 0; i < count; ++i) {
        if (address >= ranges[i].begin && address < ranges[i].end) {
            return true;
        }
    }
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &info, sizeof(info)) == 0 ||
        info.Type != MEM_IMAGE) {
        return false;
    }
    const u64 begin = reinterpret_cast<u64>(info.BaseAddress);
    ranges[count % ranges.size()] = {begin, begin + info.RegionSize};
    count = (std::min)(count + 1, ranges.size());
    return true;
}

// Walks the suspended thread's stack from its context. Only reads its memory and the unwind
// tables; allocates nothing (the thread may hold the heap lock).
size_t Walk(CONTEXT context, std::array<u64, MaxDepth>& frames) {
    size_t depth = 0;
    while (depth < MaxDepth && context.Rip != 0) {
        frames[depth++] = context.Rip;
        if (!InImage(context.Rip)) {
            break;
        }
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

void Write(State& state, bool window, const std::string& file_name) {
    using namespace Common::FS;
    // Written beside it and moved over it: a write cut short by the emulator closing left half
    // a file, without the threads after the first.
    const auto path = GetEdenPath(EdenPath::LogDir) / file_name;
    auto temporary = path;
    temporary += ".tmp";
    std::FILE* file = _wfopen(temporary.c_str(), L"w");
    if (file == nullptr) {
        return;
    }
    std::unordered_map<u64, std::string> modules;
    for (size_t i = 0; i < state.count.load(); ++i) {
        const Target& target = state.targets[i];
        const auto& stacks = window ? target.window_stacks : target.stacks;
        std::fprintf(file, "thread %s: %llu samples\n", target.name.c_str(),
                     static_cast<unsigned long long>(window ? target.window_samples
                                                            : target.samples));
        // Most frequent first.
        std::vector<std::pair<u64, const std::vector<u64>*>> order;
        order.reserve(stacks.size());
        for (const auto& [stack, seen] : stacks) {
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
    if (std::fclose(file) == 0) {
        MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
    }
}

void Run(std::stop_token stop_token) {
    State& state = Get();
    auto next_write = std::chrono::steady_clock::now() + std::chrono::seconds{10};
    std::array<u64, MaxDepth> frames{};
    std::vector<u64> stack;
    u32 window_index = 0;
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
            ++target.window_stacks[stack];
            ++target.window_samples;
        }
        if (std::chrono::steady_clock::now() >= next_write) {
            // The whole run, and each 10 s apart (nx2_samples_w<n>.txt, to pick a stretch of it).
            next_write += std::chrono::seconds{10};
            ++window_index;
            Write(state, false, "nx2_samples.txt");
            Write(state, true, fmt::format("nx2_samples_w{}.txt", window_index));
            for (size_t i = 0; i < state.count.load(); ++i) {
                state.targets[i].window_stacks.clear();
                state.targets[i].window_samples = 0;
            }
            LOG_INFO(HW_GPU, "Sampler: stacks written to nx2_samples.txt and nx2_samples_w{}.txt",
                     window_index);
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
