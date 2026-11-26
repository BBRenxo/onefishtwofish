#include "pe_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace eac {

namespace {

constexpr std::array<uint32_t, 64> kSha256K = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

inline uint32_t rotr32(uint32_t x, uint32_t n) noexcept {
    return (x >> n) | (x << (32U - n));
}

inline uint16_t read_u16_le(const uint8_t* p) noexcept {
    uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

inline uint64_t read_u64_le(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

void sha256_transform(std::array<uint32_t, 8>& state, const uint8_t block[64]) noexcept {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (uint32_t(block[i * 4 + 0]) << 24) |
               (uint32_t(block[i * 4 + 1]) << 16) |
               (uint32_t(block[i * 4 + 2]) << 8) |
               (uint32_t(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + ch + kSha256K[i] + w[i];
        const uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

std::string read_cstr_bounded(std::span<const uint8_t> data, size_t off, size_t max_len = 512) {
    if (off >= data.size()) {
        return {};
    }
    const size_t limit = std::min(data.size() - off, max_len);
    std::string out;
    out.reserve(32);
    for (size_t i = 0; i < limit; ++i) {
        const uint8_t ch = data[off + i];
        if (ch == 0) {
            return out;
        }
        if (ch < 0x20 || ch > 0x7E) {
            return {};
        }
        out.push_back(static_cast<char>(ch));
    }
    return {};
}

} // namespace

std::string compute_sha256_hex(std::span<const uint8_t> data) {
    std::array<uint32_t, 8> state = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    const size_t full_blocks = data.size() / 64;
    for (size_t i = 0; i < full_blocks; ++i) {
        sha256_transform(state, data.data() + i * 64);
    }

    uint8_t tail[128]{};
    const size_t rem = data.size() - full_blocks * 64;
    if (rem > 0) {
        std::memcpy(tail, data.data() + full_blocks * 64, rem);
    }
    tail[rem] = 0x80U;

    const size_t total_pad_len = (rem < 56) ? 64 : 128;
    const uint64_t bit_len = static_cast<uint64_t>(data.size()) * 8ULL;
    for (int i = 0; i < 8; ++i) {
        tail[total_pad_len - 8 + i] = static_cast<uint8_t>((bit_len >> (56 - i * 8)) & 0xFFU);
    }

    sha256_transform(state, tail);
    if (total_pad_len == 128) {
        sha256_transform(state, tail + 64);
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t word : state) {
        oss << std::setw(8) << word;
    }
    return oss.str();
}

std::optional<PeImage> PeImage::load_from_file(const std::string& path, std::string* err) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        if (err) *err = "Failed to open file: " + path;
        return std::nullopt;
    }

    const std::streamsize file_sz = ifs.tellg();
    if (file_sz < 0x100) {
        if (err) *err = "File too small to be a valid PE image: " + path;
        return std::nullopt;
    }

    std::vector<uint8_t> raw(static_cast<size_t>(file_sz));
    ifs.seekg(0, std::ios::beg);
    if (!ifs.read(reinterpret_cast<char*>(raw.data()), file_sz)) {
        if (err) *err = "Short read while loading file: " + path;
        return std::nullopt;
    }

    return load_from_bytes(std::move(raw), path, err);
}

std::optional<PeImage> PeImage::load_from_bytes(
    std::vector<uint8_t> bytes,
    const std::string& path,
    std::string* err) {
    if (bytes.size() < 0x100) {
        if (err) *err = "Buffer too small to be a valid PE image: " + path;
        return std::nullopt;
    }

    PeImage img;
    img.path_ = path;
    img.data_ = std::move(bytes);

    if (read_u16_le(img.data_.data()) != 0x5A4DU) {
        if (err) *err = "Missing MZ signature: " + path;
        return std::nullopt;
    }

    const uint32_t e_lfanew = read_u32_le(img.data_.data() + 0x3C);
    if (static_cast<uint64_t>(e_lfanew) + 24ULL > img.data_.size()) {
        if (err) *err = "Out-of-bounds e_lfanew: " + path;
        return std::nullopt;
    }

    if (read_u32_le(img.data_.data() + e_lfanew) != 0x00004550U) {
        if (err) *err = "Missing PE\\0\\0 signature: " + path;
        return std::nullopt;
    }

    const uint8_t* coff = img.data_.data() + e_lfanew + 4;
    img.machine_ = read_u16_le(coff + 0);
    const uint16_t num_sections = read_u16_le(coff + 2);
    img.time_date_stamp_ = read_u32_le(coff + 4);
    const uint16_t opt_hdr_size = read_u16_le(coff + 16);

    const size_t opt_off = static_cast<size_t>(e_lfanew) + 24;
    if (opt_hdr_size < 24 || opt_off + opt_hdr_size > img.data_.size()) {
        if (err) *err = "Invalid OptionalHeader bounds: " + path;
        return std::nullopt;
    }

    const uint8_t* opt = img.data_.data() + opt_off;
    const uint16_t opt_magic = read_u16_le(opt + 0);
    if (opt_magic == 0x20BU) {
        img.is_pe64_ = true;
    } else if (opt_magic == 0x10BU) {
        img.is_pe64_ = false;
    } else {
        if (err) *err = "Unsupported OptionalHeader Magic: " + path;
        return std::nullopt;
    }

    img.entry_rva_ = read_u32_le(opt + 16);
    img.checksum_ = read_u32_le(opt + 64);

    uint32_t num_rva_and_sizes = 0;
    size_t dd_off = 0;
    if (img.is_pe64_) {
        if (opt_hdr_size < 112) {
            if (err) *err = "Truncated PE32+ OptionalHeader: " + path;
            return std::nullopt;
        }
        img.image_base_ = read_u64_le(opt + 24);
        img.size_of_image_ = read_u32_le(opt + 56);
        num_rva_and_sizes = read_u32_le(opt + 108);
        dd_off = opt_off + 112;
    } else {
        if (opt_hdr_size < 96) {
            if (err) *err = "Truncated PE32 OptionalHeader: " + path;
            return std::nullopt;
        }
        img.image_base_ = read_u32_le(opt + 28);
        img.size_of_image_ = read_u32_le(opt + 56);
        num_rva_and_sizes = read_u32_le(opt + 92);
        dd_off = opt_off + 96;
    }

    const uint32_t max_dirs = std::min<uint32_t>(num_rva_and_sizes, 16U);
    auto read_dir = [&](uint32_t idx, uint32_t& out_rva, uint32_t& out_sz) {
        if (idx < max_dirs && dd_off + static_cast<size_t>(idx + 1) * 8 <= opt_off + opt_hdr_size) {
            out_rva = read_u32_le(img.data_.data() + dd_off + idx * 8);
            out_sz = read_u32_le(img.data_.data() + dd_off + idx * 8 + 4);
        }
    };

    read_dir(0, img.export_dir_rva_, img.export_dir_size_);
    read_dir(1, img.import_dir_rva_, img.import_dir_size_);
    read_dir(3, img.exception_dir_rva_, img.exception_dir_size_);

    const size_t sec_table_off = opt_off + opt_hdr_size;
    if (sec_table_off + static_cast<size_t>(num_sections) * 40 > img.data_.size()) {
        if (err) *err = "Section table exceeds file size: " + path;
        return std::nullopt;
    }

    img.sections_.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const uint8_t* sh = img.data_.data() + sec_table_off + static_cast<size_t>(i) * 40;
        SectionInfo s;
        size_t name_len = 0;
        while (name_len < 8 && sh[name_len] != 0) {
            ++name_len;
        }
        s.name.assign(reinterpret_cast<const char*>(sh), name_len);
        s.virtual_size = read_u32_le(sh + 8);
        s.virtual_address = read_u32_le(sh + 12);
        s.raw_size = read_u32_le(sh + 16);
        s.raw_ptr = read_u32_le(sh + 20);
        s.characteristics = read_u32_le(sh + 36);
        img.sections_.push_back(std::move(s));
    }

    return img;
}

std::string PeImage::sha256_hex() const {
    return compute_sha256_hex(data_);
}

std::optional<size_t> PeImage::rva_to_offset(uint32_t rva) const noexcept {
    uint32_t first_sec_va = 0xFFFFFFFFU;
    for (const auto& sec : sections_) {
        if (sec.virtual_address > 0 && sec.virtual_address < first_sec_va) {
            first_sec_va = sec.virtual_address;
        }
    }
    if (rva < first_sec_va && rva < data_.size()) {
        return static_cast<size_t>(rva);
    }

    for (const auto& sec : sections_) {
        const uint32_t span_max = std::max(sec.virtual_size, sec.raw_size);
        if (rva >= sec.virtual_address && (rva - sec.virtual_address) < span_max) {
            const uint32_t delta = rva - sec.virtual_address;
            if (delta >= sec.raw_size) {
                return std::nullopt;
            }
            const uint64_t file_off = static_cast<uint64_t>(sec.raw_ptr) + delta;
            if (file_off < data_.size()) {
                return static_cast<size_t>(file_off);
            }
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::optional<uint32_t> PeImage::offset_to_rva(size_t offset) const noexcept {
    if (offset >= data_.size()) {
        return std::nullopt;
    }
    for (const auto& sec : sections_) {
        if (offset >= sec.raw_ptr && (offset - sec.raw_ptr) < sec.raw_size) {
            return sec.virtual_address + static_cast<uint32_t>(offset - sec.raw_ptr);
        }
    }
    uint32_t first_sec_raw = 0xFFFFFFFFU;
    for (const auto& sec : sections_) {
        if (sec.raw_ptr > 0 && sec.raw_ptr < first_sec_raw) {
            first_sec_raw = sec.raw_ptr;
        }
    }
    if (offset < first_sec_raw) {
        return static_cast<uint32_t>(offset);
    }
    return std::nullopt;
}

std::span<const uint8_t> PeImage::slice_rva(uint32_t rva, size_t len) const noexcept {
    if (len == 0) {
        return {};
    }
    const auto off_opt = rva_to_offset(rva);
    if (!off_opt.has_value()) {
        return {};
    }
    const size_t off = *off_opt;
    if (off + len > data_.size()) {
        return {};
    }
    for (const auto& sec : sections_) {
        const uint32_t span_max = std::max(sec.virtual_size, sec.raw_size);
        if (rva >= sec.virtual_address && (rva - sec.virtual_address) < span_max) {
            const uint32_t delta = rva - sec.virtual_address;
            if (static_cast<uint64_t>(delta) + len > sec.raw_size) {
                return {};
            }
            break;
        }
    }
    return std::span<const uint8_t>(data_.data() + off, len);
}

std::vector<PdataEntry> PeImage::parse_pdata() const {
    std::vector<PdataEntry> out;
    if (!is_pe64_ || exception_dir_rva_ == 0 || exception_dir_size_ < 12) {
        return out;
    }
    const size_t count = exception_dir_size_ / 12;
    const auto bytes = slice_rva(exception_dir_rva_, count * 12);
    if (bytes.empty()) {
        return out;
    }
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const uint32_t begin_rva = read_u32_le(bytes.data() + i * 12 + 0);
        const uint32_t end_rva = read_u32_le(bytes.data() + i * 12 + 4);
        const uint32_t unwind_rva = read_u32_le(bytes.data() + i * 12 + 8);
        if (begin_rva == 0 && end_rva == 0) {
            break;
        }
        out.push_back(PdataEntry{begin_rva, end_rva, unwind_rva});
    }
    return out;
}

std::vector<ImportEntry> PeImage::parse_imports_at_dir(uint32_t import_dir_rva, uint32_t import_dir_size) const {
    std::vector<ImportEntry> out;
    if (import_dir_rva == 0) {
        return out;
    }
    const size_t max_descs = (import_dir_size >= 20) ? (import_dir_size / 20) : 512;
    for (size_t d = 0; d < max_descs; ++d) {
        const auto desc_bytes = slice_rva(import_dir_rva + static_cast<uint32_t>(d * 20), 20);
        if (desc_bytes.size() < 20) {
            break;
        }
        const uint32_t oft = read_u32_le(desc_bytes.data() + 0);
        const uint32_t name_rva = read_u32_le(desc_bytes.data() + 12);
        const uint32_t ft = read_u32_le(desc_bytes.data() + 16);
        if (oft == 0 && name_rva == 0 && ft == 0) {
            break;
        }
        if (name_rva == 0 || ft == 0) {
            break;
        }
        const auto name_off = rva_to_offset(name_rva);
        if (!name_off.has_value()) {
            break;
        }
        const std::string dll_name = read_cstr_bounded(data_, *name_off, 256);
        if (dll_name.empty()) {
            break;
        }

        const uint32_t thunk_base = (oft != 0 && rva_to_offset(oft).has_value()) ? oft : ft;
        const uint32_t ptr_sz = is_pe64_ ? 8U : 4U;

        for (uint32_t idx = 0; idx < 16384U; ++idx) {
            const auto tbytes = slice_rva(thunk_base + idx * ptr_sz, ptr_sz);
            if (tbytes.size() < ptr_sz) {
                break;
            }
            const uint64_t val = is_pe64_ ? read_u64_le(tbytes.data())
                                          : static_cast<uint64_t>(read_u32_le(tbytes.data()));
            if (val == 0) {
                break;
            }

            ImportEntry entry;
            entry.dll_name = dll_name;
            entry.iat_rva = ft + idx * ptr_sz;

            const uint64_t ord_flag = is_pe64_ ? (1ULL << 63) : (1ULL << 31);
            if ((val & ord_flag) != 0) {
                entry.by_ordinal = true;
                entry.ordinal = static_cast<uint16_t>(val & 0xFFFFU);
                entry.func_name = "#" + std::to_string(entry.ordinal);
            } else {
                const uint32_t ibn_rva = static_cast<uint32_t>(val & 0x7FFFFFFFU);
                const auto ibn_off = rva_to_offset(ibn_rva);
                if (!ibn_off.has_value() || *ibn_off + 2 >= data_.size()) {
                    entry.func_name = "<unresolved_rva>";
                } else {
                    entry.ordinal = read_u16_le(data_.data() + *ibn_off);
                    entry.func_name = read_cstr_bounded(data_, *ibn_off + 2, 512);
                    if (entry.func_name.empty()) {
                        entry.func_name = "<non_ascii_import>";
                    }
                }
            }
            out.push_back(std::move(entry));
        }
    }
    return out;
}

std::vector<ImportEntry> PeImage::parse_standard_imports() const {
    return parse_imports_at_dir(import_dir_rva_, import_dir_size_);
}

std::vector<ImportEntry> PeImage::parse_bearimp_imports() const {
    for (const auto& sec : sections_) {
        if (sec.name == ".bearimp") {
            return parse_imports_at_dir(sec.virtual_address, sec.virtual_size);
        }
    }
    return {};
}

std::vector<ExportEntry> PeImage::parse_exports() const {
    std::vector<ExportEntry> out;
    if (export_dir_rva_ == 0 || export_dir_size_ < 40) {
        return out;
    }
    const auto ed = slice_rva(export_dir_rva_, 40);
    if (ed.size() < 40) {
        return out;
    }

    const uint32_t ord_base = read_u32_le(ed.data() + 16);
    const uint32_t num_funcs = read_u32_le(ed.data() + 20);
    const uint32_t num_names = read_u32_le(ed.data() + 24);
    const uint32_t funcs_rva = read_u32_le(ed.data() + 28);
    const uint32_t names_rva = read_u32_le(ed.data() + 32);
    const uint32_t ords_rva = read_u32_le(ed.data() + 36);

    if (num_funcs == 0 || num_funcs > 65536) {
        return out;
    }

    const auto func_tbl = slice_rva(funcs_rva, static_cast<size_t>(num_funcs) * 4);
    if (func_tbl.size() < static_cast<size_t>(num_funcs) * 4) {
        return out;
    }

    std::vector<std::string> func_names(num_funcs);
    if (num_names > 0 && num_names <= 65536) {
        const auto name_tbl = slice_rva(names_rva, static_cast<size_t>(num_names) * 4);
        const auto ord_tbl = slice_rva(ords_rva, static_cast<size_t>(num_names) * 2);
        if (name_tbl.size() == static_cast<size_t>(num_names) * 4 &&
            ord_tbl.size() == static_cast<size_t>(num_names) * 2) {
            for (uint32_t i = 0; i < num_names; ++i) {
                const uint16_t fn_idx = read_u16_le(ord_tbl.data() + i * 2);
                const uint32_t nm_rva = read_u32_le(name_tbl.data() + i * 4);
                const auto nm_off = rva_to_offset(nm_rva);
                if (fn_idx < num_funcs && nm_off.has_value()) {
                    func_names[fn_idx] = read_cstr_bounded(data_, *nm_off, 512);
                }
            }
        }
    }

    out.reserve(num_funcs);
    for (uint32_t i = 0; i < num_funcs; ++i) {
        const uint32_t fn_rva = read_u32_le(func_tbl.data() + i * 4);
        if (fn_rva == 0) {
            continue;
        }
        ExportEntry e;
        e.ordinal = ord_base + i;
        e.rva = fn_rva;
        e.name = func_names[i].empty() ? ("#" + std::to_string(e.ordinal)) : func_names[i];
        e.is_forwarded = (fn_rva >= export_dir_rva_ && fn_rva < export_dir_rva_ + export_dir_size_);
        out.push_back(std::move(e));
    }
    return out;
}

} // namespace eac
