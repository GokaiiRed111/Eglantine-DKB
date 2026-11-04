// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2018 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "common/common_funcs.h"
#include "common/hex_util.h"
#include "common/logging.h"
#include "common/lz4_compression.h"
#include "common/zbic_compression.h"
#include "common/settings.h"
#include "common/swap.h"
#include "core/core.h"
#include "core/file_sys/patch_manager.h"
#include "core/hle/kernel/code_set.h"
#include "core/hle/kernel/k_page_table.h"
#include "core/hle/kernel/k_process.h"
#include "core/hle/kernel/k_thread.h"
#include "core/loader/nso.h"
#include "core/memory.h"

#ifdef HAS_NCE
#include "core/arm/nce/patcher.h"
#endif

namespace Loader {
namespace {
struct MODHeader {
    u32_le magic;
    u32_le dynamic_offset;
    u32_le bss_start_offset;
    u32_le bss_end_offset;
    u32_le eh_frame_hdr_start_offset;
    u32_le eh_frame_hdr_end_offset;
    u32_le module_offset; // Offset to runtime-generated module object. typically equal to .bss base
};
static_assert(sizeof(MODHeader) == 0x1c, "MODHeader has incorrect size.");

constexpr u32 PageAlignSize(u32 size) {
    return static_cast<u32>((size + Core::Memory::YUZU_PAGEMASK) & ~Core::Memory::YUZU_PAGEMASK);
}

// The Switch 2 SDK's nn::vi::detail::DefaultDisplay::QueryVrrSupported learns VRR support from a
// display mode capability event Eden never signals, so it reports none. Title 4 then assumes a fixed
// 60 Hz display and its speed swings with the frame rate; told VRR works, it enables it and times
// its frames itself. Make the exported function store true and succeed (any SDK version: found by
// name). EDEN_NX2_REPORT_VRR=0 leaves it alone.
void ReportVrrSupported(std::span<u8> image, std::string_view module_name) {
    static const bool enabled = [] {
        const char* value = std::getenv("EDEN_NX2_REPORT_VRR");
        return value == nullptr || value[0] != '0';
    }();
    if (!enabled || image.size() < 8) {
        return;
    }
    const auto read32 = [&](u64 offset) -> std::optional<u32> {
        if (offset + 4 > image.size()) return std::nullopt;
        u32 value;
        std::memcpy(&value, image.data() + offset, 4);
        return value;
    };
    const auto read64 = [&](u64 offset) -> std::optional<u64> {
        if (offset + 8 > image.size()) return std::nullopt;
        u64 value;
        std::memcpy(&value, image.data() + offset, 8);
        return value;
    };
    const auto mod0 = read32(4);
    if (!mod0 || read32(*mod0) != Common::MakeMagic('M', 'O', 'D', '0')) {
        return;
    }
    const auto dynamic_rel = read32(*mod0 + 4);
    if (!dynamic_rel) {
        return;
    }
    u64 symtab = 0, strtab = 0, strsz = 0, hash = 0;
    for (u64 entry = *mod0 + static_cast<s32>(*dynamic_rel);; entry += 16) {
        const auto tag = read64(entry), value = read64(entry + 8);
        if (!tag || !value || *tag == 0) break;
        switch (*tag) {
        case 4: hash = *value; break;    // DT_HASH
        case 5: strtab = *value; break;  // DT_STRTAB
        case 6: symtab = *value; break;  // DT_SYMTAB
        case 10: strsz = *value; break;  // DT_STRSZ
        default: break;
        }
    }
    if (symtab == 0 || strtab == 0) {
        return;
    }
    // DT_HASH gives the symbol count; with only DT_GNU_HASH (the Switch 2 SDK) the table runs up
    // to the string table, which follows it.
    std::optional<u32> count = hash != 0 ? read32(hash + 4) : std::nullopt;
    if (!count && strtab > symtab) {
        count = static_cast<u32>((strtab - symtab) / 24);
    }
    if (!count) {
        return;
    }
    constexpr std::string_view Target = "_ZNK2nn2vi6detail14DefaultDisplay17QueryVrrSupportedEPb";
    for (u32 index = 0; index < *count; ++index) {
        const u64 symbol = symtab + u64{index} * 24;
        const auto name_offset = read32(symbol);
        const auto value = read64(symbol + 8);
        if (!name_offset || !value || *value == 0 || *name_offset + Target.size() >= strsz ||
            strtab + *name_offset + Target.size() >= image.size()) {
            continue;
        }
        const auto* name = reinterpret_cast<const char*>(image.data() + strtab + *name_offset);
        if (std::string_view{name, Target.size()} != Target || name[Target.size()] != '\0') {
            continue;
        }
        // mov w8, #1; strb w8, [x1]; mov w0, #0; ret
        static constexpr std::array<u32, 4> Code{0x52800028, 0x39000028, 0x52800000, 0xd65f03c0};
        if (*value + sizeof(Code) > image.size()) {
            return;
        }
        std::memcpy(image.data() + *value, Code.data(), sizeof(Code));
        LOG_INFO(Loader, "{}: QueryVrrSupported at {:#x} now reports VRR support", module_name, *value);
        return;
    }
}
} // Anonymous namespace

bool NSOHeader::IsSegmentCompressed(size_t segment_num) const {
    ASSERT_MSG(segment_num < 3, "Invalid segment {}", segment_num);
    return ((flags >> segment_num) & 1) != 0;
}

AppLoader_NSO::AppLoader_NSO(FileSys::VirtualFile file_) : AppLoader(std::move(file_)) {}

FileType AppLoader_NSO::IdentifyType(const FileSys::VirtualFile& in_file) {
    u32 magic = 0;
    if (in_file->ReadObject(&magic) != sizeof(magic)) {
        return FileType::Error;
    }

    if (Common::MakeMagic('N', 'S', 'O', '0') != magic) {
        return FileType::Error;
    }

    return FileType::NSO;
}

std::optional<VAddr> AppLoader_NSO::LoadModule(Kernel::KProcess& process, Core::System& system, const FileSys::VfsFile& nso_file, VAddr load_base, bool should_pass_arguments, bool load_into_process, std::optional<FileSys::PatchManager> pm, std::vector<Core::NCE::Patcher>* patches, s32 patch_index) {
    if (nso_file.GetSize() < sizeof(NSOHeader))
        return std::nullopt;
    NSOHeader nso_header{};
    if (sizeof(NSOHeader) != nso_file.ReadObject(&nso_header))
        return std::nullopt;
    if (nso_header.magic != Common::MakeMagic('N', 'S', 'O', '0'))
        return std::nullopt;
    if (nso_header.segments.empty())
        return std::nullopt;

    // Allocate some space at the beginning if we are patching in PreText mode.
    const size_t module_start = [&]() -> size_t {
#ifdef HAS_NCE
        if (patches && load_into_process) {
            auto* patch = &patches->operator[](patch_index);
            if (patch->GetPatchMode() == Core::NCE::PatchMode::PreText) {
                return patch->GetSectionSize();
            } else if (patch->GetPatchMode() == Core::NCE::PatchMode::Split) {
                return patch->GetPreSectionSize();
            }
        }
#endif
        return 0;
    }();

    auto const last_segment_it = &nso_header.segments[nso_header.segments.size() - 1];
    // Build program image directly in codeset memory :)
    Kernel::CodeSet codeset;
    codeset.memory.resize(module_start + last_segment_it->location + last_segment_it->size);
    {
        std::vector<u8> compressed_data(*std::ranges::max_element(nso_header.segments_compressed_size));
        std::vector<u8> decompressed_size(std::ranges::max_element(nso_header.segments, [](auto const& a, auto const& b) {
            return a.size < b.size;
        })->size);
        for (std::size_t i = 0; i < nso_header.segments.size(); ++i) {
            nso_file.Read(compressed_data.data(), nso_header.segments_compressed_size[i], nso_header.segments[i].offset);
            if (nso_header.IsSegmentCompressed(i)) {
                if (nso_header.IsZBICCompressed()) {
                    // ZBIC compression
                    const int r = Common::Compression::DecompressDataZBIC(
                        std::span<u8>{decompressed_size}.first(nso_header.segments[i].size),
                        std::span<const u8>{compressed_data}.first(nso_header.segments_compressed_size[i])
                    );
                    ASSERT(r > 0);
                } else {
                    // LZ4 compression
                    int r = Common::Compression::DecompressDataLZ4(
                        decompressed_size.data(),
                        nso_header.segments[i].size,
                        compressed_data.data(),
                        nso_header.segments_compressed_size[i]
                    );
                    ASSERT(r == int(nso_header.segments[i].size));
                }

                std::memcpy(
                    codeset.memory.data() + module_start + nso_header.segments[i].location,
                    decompressed_size.data(),
                    nso_header.segments[i].size
                );
            } else {
                // Not compressed
                std::memcpy(
                    codeset.memory.data() + module_start + nso_header.segments[i].location,
                    compressed_data.data(),
                    nso_header.segments[i].size
                );
            }
            codeset.segments[i].addr = module_start + nso_header.segments[i].location;
            codeset.segments[i].offset = module_start + nso_header.segments[i].location;
            codeset.segments[i].size = nso_header.segments[i].size;
        }
    }

    if (should_pass_arguments && !Settings::values.program_args.GetValue().empty()) {
        const auto arg_data{Settings::values.program_args.GetValue()};

        codeset.DataSegment().size += NSO_ARGUMENT_DATA_ALLOCATION_SIZE;
        NSOArgumentHeader args_header{NSO_ARGUMENT_DATA_ALLOCATION_SIZE, static_cast<u32_le>(arg_data.size()), {}};
        const auto end_offset = codeset.memory.size();
        codeset.memory.resize(u32(codeset.memory.size()) + NSO_ARGUMENT_DATA_ALLOCATION_SIZE);
        std::memcpy(codeset.memory.data() + end_offset, &args_header, sizeof(NSOArgumentHeader));
        std::memcpy(codeset.memory.data() + end_offset + sizeof(NSOArgumentHeader), arg_data.data(), arg_data.size());
    }

    codeset.DataSegment().size += nso_header.segments[2].bss_size;
    u32 image_size = PageAlignSize(u32(codeset.memory.size()) + nso_header.segments[2].bss_size);
    codeset.memory.resize(image_size);

    for (std::size_t i = 0; i < nso_header.segments.size(); ++i) {
        codeset.segments[i].size = PageAlignSize(codeset.segments[i].size);
    }

    // Apply patches if necessary
    const auto name = nso_file.GetName();
    if (pm && (pm->HasNSOPatch(nso_header.build_id, name) || Settings::values.dump_nso)) {
        std::span<u8> patchable_section(codeset.memory.data() + module_start, codeset.memory.size() - module_start);
        std::vector<u8> pi_header(sizeof(NSOHeader) + patchable_section.size());
        std::memcpy(pi_header.data(), &nso_header, sizeof(NSOHeader));
        std::memcpy(pi_header.data() + sizeof(NSOHeader), patchable_section.data(),
                    patchable_section.size());

        pi_header = pm->PatchNSO(pi_header, name);

        std::copy(pi_header.begin() + sizeof(NSOHeader), pi_header.end(), patchable_section.data());
    }
    // This fork reports VRR to Bananza alone (ZendNevs's reports it to every game).
    const bool dk_dynamic = process.GetProgramId() == 0x040074A01BF12000ULL &&
                            Settings::values.dk_dynamic_fps.GetValue();
    if (name == "sdk" && dk_dynamic) {
        ReportVrrSupported(std::span{codeset.memory}.subspan(module_start), name);
    }

    // Donkey Kong Bananza picks its frame rate target from the time of a frame: above 40 fps it
    // sleeps to the target and advances its clock by 60/target, below 40 it uses a whole interval.
    // That choice reads [fw+0x128], the CPU's calc time, which is short under emulation where the
    // GPU thread is the slow part: it stayed at 60 and the game ran in slow motion below that.
    // Point it at [fw+0xe8], the whole frame, and take the game's own sleep out of that time
    // (start of frame + sleep), or a lowered target could never rise again. The sleep's check moves
    // to free space in the text segment's last page.
    // Below 40 fps the game ran with no sleep, so a frame shorter than its interval sped it up and
    // a longer one slowed it down: sleep there too, to 60/interval.
    // The clock's step was still 60/target, so a frame longer than its target ran in slow motion.
    // With the sleep, a frame lasts the longer of its target and its work: step by that, up to 2.5
    // (24 fps), since 4 fell into a 3 fps loop: a long step makes a long frame, so a long step.
    // The controller, which has the frame time in 60ths, keeps it in an unused field.
    if (Settings::values.dk_dynamic_fps.GetValue() && name == "main" &&
        process.GetProgramId() == 0x040074A01BF12000ULL) {
        const auto& text = nso_header.segments[0];
        u8* const code = codeset.memory.data() + module_start + text.location;
        const size_t count = text.size / sizeof(u32);
        const auto word = [code](size_t index) {
            u32 value;
            std::memcpy(&value, code + index * sizeof(u32), sizeof(value));
            return value;
        };
        const auto put = [code](size_t index, u32 value) {
            std::memcpy(code + index * sizeof(u32), &value, sizeof(value));
        };
        const auto branch = [](size_t from, size_t to) {
            return 0x14000000U |
                   (static_cast<u32>(static_cast<s64>(to) - static_cast<s64>(from)) & 0x3FFFFFFU);
        };
        size_t controller = 0, controller_matches = 0, sleep = 0, sleep_matches = 0;
        size_t step = 0, step_matches = 0;
        for (size_t i = 1; i + 8 < count; ++i) {
            if (word(i) == 0xBD405100 && word(i + 1) == 0x52A84E08 && word(i + 2) == 0x1E270101 &&
                word(i + 6) == 0x5E21D800 && word(i + 7) == 0x1E201820 && word(i + 8) == 0xBD000100) {
                step = i; // ldr s0, [x8, #0x50]; ...; scvtf s0, s0; fdiv s0, s1, s0; str s0, [x8]
                ++step_matches;
            }
            if (word(i) == 0xF9409429 && word(i + 1) == 0x7100015F && word(i + 2) == 0xFA400924) {
                controller = i; // ldr x9, [x1, #0x128]; cmp w10, #0; ccmp x9, #0, #4, eq
                ++controller_matches;
            }
            if (word(i) == 0xEB080120 && word(i - 1) == 0x9E380009 &&
                (word(i + 1) & 0xFF00001F) == 0x5400000D && (word(i + 2) >> 26) == 0x25) {
                sleep = i; // fcvtzs x9, s0; subs x0, x9, x8; b.le; bl
                ++sleep_matches;
            }
        }
        // The two checks sit at fixed distances from the matches above.
        const size_t low_check = sleep - 14, frame_time = controller + 14;
        const bool extras_found = sleep_matches == 1 && controller_matches == 1 && step_matches == 1 &&
                                  word(low_check - 1) == 0x39472e68U && word(low_check) == 0x350006a8U &&
                                  word(frame_time) == 0x2944266dU;
        constexpr size_t CaveWords = 19;
        const size_t cave = (text.size + 15) / 16 * 4;
        if (extras_found && (cave + CaveWords) * sizeof(u32) <= PageAlignSize(text.size)) {
            const size_t no_sleep = sleep + 1 + ((word(sleep + 1) >> 5) & 0x7FFFF);
            put(cave, 0xEB080120);                         // subs x0, x9, x8
            put(cave + 1, 0x5400004C);                     // b.gt +8
            put(cave + 2, branch(cave + 2, no_sleep));     // b (the old b.le's target)
            put(cave + 3, 0xF9407A6A);                     // ldr x10, [x19, #0xf0]
            put(cave + 4, 0x8B00014A);                     // add x10, x10, x0
            put(cave + 5, 0xF9007A6A);                     // str x10, [x19, #0xf0]
            put(cave + 6, branch(cave + 6, sleep + 2));    // back to the sleep
            put(sleep, branch(sleep, cave));
            put(controller, 0xF9407429);                   // ldr x9, [x1, #0xe8]
            put(low_check, 0xD503201F);                    // nop: sleep below 40 fps too
            put(cave + 7, 0xBD005E60);                     // str s0, [x19, #0x5c]: frame in 60ths
            put(cave + 8, word(frame_time));
            put(cave + 9, branch(cave + 9, frame_time + 1));
            put(frame_time, branch(frame_time, cave + 7));
            put(cave + 10, 0xBD405D02);                    // ldr s2, [x8, #0x5c]
            put(cave + 11, word(step + 1));                // mov w8, #60.0
            put(cave + 12, word(step + 2));                // fmov s1, w8
            put(cave + 13, word(step + 6));                // scvtf s0, s0
            put(cave + 14, word(step + 7));                // fdiv s0, s1, s0
            put(cave + 15, 0x1E226800);                    // fmaxnm s0, s0, s2
            put(cave + 16, 0x1E209001);                    // fmov s1, #2.5
            put(cave + 17, 0x1E217800);                    // fminnm s0, s0, s1
            put(cave + 18, branch(cave + 18, step + 3));
            put(step + 1, branch(step + 1, cave + 10));
            put(step + 6, 0xD503201F);                     // nop, done in the cave
            put(step + 7, 0xD503201F);                     // nop, done in the cave
            LOG_INFO(Loader, "Donkey Kong Bananza: dynamic FPS on (main+{:#x}, main+{:#x})",
                     text.location + controller * sizeof(u32),
                     text.location + sleep * sizeof(u32));
        } else {
            LOG_WARNING(Loader, "Donkey Kong Bananza: dynamic FPS not applied ({}, {}, {} matches)",
                        controller_matches, sleep_matches, step_matches);
        }
    }


#ifdef HAS_NCE
    // If we are computing the process code layout and using nce backend, patch.
    const auto& code = codeset.CodeSegment();
    auto* patch = patches ? &patches->operator[](patch_index) : nullptr;
    if (patch && !load_into_process) {
        //Set module ID using build_id from the NSO header
        patch->SetModuleID(nso_header.build_id);
        // Patch SVCs and MRS calls in the guest code
        while (!patch->PatchText(codeset.memory, code)) {
            patch = &patches->emplace_back();
            patch->SetModuleID(nso_header.build_id);  // In case the patcher is changed for big modules, the new patcher should also have the build_id
        }
    } else if (patch) {
        // Relocate code patch and copy to the program image.
        // Save size before RelocateAndCopy (which may resize)
        const size_t size_before_relocate = codeset.memory.size();
        if (patch->RelocateAndCopy(load_base, code, codeset.memory, &process.GetPostHandlers())) {
            // Update patch section.
            auto& patch_segment = codeset.PatchSegment();
            auto& post_patch_segment = codeset.PostPatchSegment();
            const auto patch_mode = patch->GetPatchMode();
            if (patch_mode == Core::NCE::PatchMode::PreText) {
                patch_segment.addr = 0;
                patch_segment.size = static_cast<u32>(patch->GetSectionSize());
            } else if (patch_mode == Core::NCE::PatchMode::Split) {
                // For Split-mode, we are using pre-patch buffer at start, post-patch buffer at end
                patch_segment.addr = 0;
                patch_segment.size = static_cast<u32>(patch->GetPreSectionSize());
                post_patch_segment.addr = size_before_relocate;
                post_patch_segment.size = static_cast<u32>(patch->GetSectionSize());
            } else {
                patch_segment.addr = image_size;
                patch_segment.size = static_cast<u32>(patch->GetSectionSize());
            }
        }

        // Refresh image_size to take account the patch section if it was added by RelocateAndCopy
        image_size = static_cast<u32>(codeset.memory.size());
    }
#endif

    // If we aren't actually loading (i.e. just computing the process code layout), we are done
    if (!load_into_process) {
#ifdef HAS_NCE
        // Ok, so for Split mode, we need to account for pre-patch and post-patch space
        // which will be added during RelocateAndCopy in the second pass. Where it crashed
        // in Android Studio at PreText. May be a better way. Works for now.
        if (patch && patch->GetPatchMode() == Core::NCE::PatchMode::Split) {
            return load_base + patch->GetPreSectionSize() + image_size + patch->GetSectionSize();
        } else if (patch && patch->GetPatchMode() == Core::NCE::PatchMode::PreText) {
            return load_base + patch->GetSectionSize() + image_size;
        } else if (patch && patch->GetPatchMode() == Core::NCE::PatchMode::PostData) {
            return load_base + image_size + patch->GetSectionSize();
        }
#endif
        return load_base + image_size;
    }

    // Apply cheats if they exist and the program has a valid title ID
    if (pm) {
        // TODO(Maufeat): Check if there is a better way to check
        if (name == "main")
            system.SetApplicationProcessBuildID(nso_header.build_id);

        const auto cheats = pm->CreateCheatList(nso_header.build_id);
        if (!cheats.empty()) {
            system.RegisterCheatList(cheats, nso_header.build_id, load_base, image_size);
        }
    }

    // Load codeset for current process
    LOG_INFO(Loader, "Module {} loaded at {:#x} (size {:#x})", nso_file.GetName(), load_base, image_size);
    process.LoadModule(system.Kernel(), std::move(codeset), load_base);
    return load_base + image_size;
}

AppLoader_NSO::LoadResult AppLoader_NSO::Load(Kernel::KProcess& process, Core::System& system) {
    if (is_loaded) {
        return {ResultStatus::ErrorAlreadyLoaded, {}};
    }

    modules.clear();

    // Load module
    const VAddr base_address = GetInteger(process.GetEntryPoint());
    if (!LoadModule(process, system, *file, base_address, true, true)) {
        return {ResultStatus::ErrorLoadingNSO, {}};
    }

    modules.insert_or_assign(base_address, file->GetName());
    LOG_DEBUG(Loader, "loaded module {} @ {:#x}", file->GetName(), base_address);

    is_loaded = true;
    return {ResultStatus::Success, LoadParameters{Kernel::KThread::DefaultThreadPriority,
                                                  Core::Memory::DEFAULT_STACK_SIZE}};
}

ResultStatus AppLoader_NSO::ReadNSOModules(Modules& out_modules) {
    out_modules = this->modules;
    return ResultStatus::Success;
}

} // namespace Loader
