#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace eac {

struct SectionInfo {
    std::string name;
    uint32_t virtual_address = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t raw_size = 0;
    uint32_t characteristics = 0;
};

struct ImportEntry {
    std::string dll_name;
    std::string func_name;
    uint16_t ordinal = 0;
    bool by_ordinal = false;
    uint32_t iat_rva = 0;
};

struct ExportEntry {
    std::string name;
    uint32_t ordinal = 0;
    uint32_t rva = 0;
    bool is_forwarded = false;
};

struct PdataEntry {
    uint32_t begin_rva = 0;
    uint32_t end_rva = 0;
    uint32_t unwind_info_rva = 0;
};

class PeImage {
public:
    static std::optional<PeImage> load_from_file(const std::string& path, std::string* err = nullptr);
    static std::optional<PeImage> load_from_bytes(
        std::vector<uint8_t> bytes,
        const std::string& virtual_path = "<memory>",
        std::string* err = nullptr);

    const std::string& path() const noexcept { return path_; }
    std::span<const uint8_t> raw_bytes() const noexcept { return data_; }
    bool is_pe64() const noexcept { return is_pe64_; }
    uint16_t machine() const noexcept { return machine_; }
    uint64_t image_base() const noexcept { return image_base_; }
    uint32_t size_of_image() const noexcept { return size_of_image_; }
    uint32_t entry_rva() const noexcept { return entry_rva_; }
    uint32_t time_date_stamp() const noexcept { return time_date_stamp_; }
    uint32_t checksum() const noexcept { return checksum_; }
    std::string sha256_hex() const;

    const std::vector<SectionInfo>& sections() const noexcept { return sections_; }
    std::optional<size_t> rva_to_offset(uint32_t rva) const noexcept;
    std::optional<uint32_t> offset_to_rva(size_t offset) const noexcept;
    std::span<const uint8_t> slice_rva(uint32_t rva, size_t len) const noexcept;

    std::vector<PdataEntry> parse_pdata() const;
    std::vector<ImportEntry> parse_imports_at_dir(uint32_t import_dir_rva, uint32_t import_dir_size = 0) const;
    std::vector<ImportEntry> parse_standard_imports() const;
    std::vector<ImportEntry> parse_bearimp_imports() const;
    std::vector<ExportEntry> parse_exports() const;

private:
    std::string path_;
    std::vector<uint8_t> data_;
    bool is_pe64_ = false;
    uint16_t machine_ = 0;
    uint64_t image_base_ = 0;
    uint32_t size_of_image_ = 0;
    uint32_t entry_rva_ = 0;
    uint32_t time_date_stamp_ = 0;
    uint32_t checksum_ = 0;
    uint32_t import_dir_rva_ = 0;
    uint32_t import_dir_size_ = 0;
    uint32_t export_dir_rva_ = 0;
    uint32_t export_dir_size_ = 0;
    uint32_t exception_dir_rva_ = 0;
    uint32_t exception_dir_size_ = 0;
    std::vector<SectionInfo> sections_;
};

std::string compute_sha256_hex(std::span<const uint8_t> data);

} // namespace eac
