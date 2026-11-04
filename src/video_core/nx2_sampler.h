// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

namespace VideoCommon::Nx2Sampler {

/// EDEN_NX2_SAMPLE=1 (Windows): samples the calling thread's call stack about every millisecond
/// from a separate thread and writes the stacks, with how often each was seen, to
/// nx2_samples.txt in the log directory every 10 s (addresses as module+offset, for the linker's
/// map file). Call from the thread itself, once, as it starts. Does nothing otherwise.
void RegisterCurrentThread(const char* name);

} // namespace VideoCommon::Nx2Sampler
