#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace fs = std::filesystem;

namespace {

enum class Severity {
    High,
    Medium,
    Low
};

struct Options {
    bool json = false;
    bool entropy = true;
    bool quiet = false;
    std::uintmax_t max_size = 2U * 1024U * 1024U;
    std::vector<fs::path> paths;
};

struct Rule {
    std::string id;
    std::string name;
    Severity severity;
    std::regex pattern;
};

struct Finding {
    std::string rule;
    Severity severity;
    std::string path;
    std::size_t line = 0;
    std::string redacted;
};

struct Span {
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct Stats {
    std::size_t files_scanned = 0;
    std::size_t files_skipped = 0;
    std::size_t high = 0;
    std::size_t medium = 0;
    std::size_t low = 0;
    long long duration_ms = 0;
};

struct ScanResult {
    std::vector<Finding> findings;
    Stats stats;
    bool io_error = false;
};

std::string severity_to_string(Severity severity) {
    switch (severity) {
    case Severity::High:
        return "HIGH";
    case Severity::Medium:
        return "MEDIUM";
    case Severity::Low:
        return "LOW";
    }
    return "LOW";
}

const char *severity_color(Severity severity) {
    switch (severity) {
    case Severity::High:
        return "\033[31m";
    case Severity::Medium:
        return "\033[33m";
    case Severity::Low:
        return "\033[36m";
    }
    return "";
}

bool stdout_is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(1) != 0;
#endif
}

void enable_ansi_if_possible() {
#ifdef _WIN32
    HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (handle == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD mode = 0;
    if (GetConsoleMode(handle, &mode) == 0) {
        return;
    }
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    static_cast<void>(SetConsoleMode(handle, mode));
#endif
}

std::string usage() {
    return "leakhound [options] <path>...\n"
           "  --json           machine-readable output (one JSON object, findings array)\n"
           "  --no-entropy     disable entropy heuristics (pattern rules only)\n"
           "  --max-size N     skip files larger than N bytes (default 2 MiB)\n"
           "  --quiet          suppress per-finding lines, print summary only\n"
           "  -h, --help       usage\n";
}

bool parse_uintmax(const std::string &text, std::uintmax_t &value) {
    if (text.empty()) {
        return false;
    }
    std::uintmax_t result = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') {
            return false;
        }
        const std::uintmax_t digit = static_cast<std::uintmax_t>(ch - '0');
        if (result > (std::numeric_limits<std::uintmax_t>::max() - digit) / 10U) {
            return false;
        }
        result = result * 10U + digit;
    }
    value = result;
    return true;
}

bool parse_args(int argc, char **argv, Options &options, bool &help, std::string &error) {
    help = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        if (arg == "--json") {
            options.json = true;
        } else if (arg == "--no-entropy") {
            options.entropy = false;
        } else if (arg == "--quiet") {
            options.quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            help = true;
            return true;
        } else if (arg == "--max-size") {
            if (i + 1 >= argc) {
                error = "--max-size requires a value";
                return false;
            }
            ++i;
            if (!parse_uintmax(argv[i], options.max_size)) {
                error = "--max-size must be a non-negative integer";
                return false;
            }
        } else if (!arg.empty() && arg[0] == '-') {
            error = "unknown option: " + arg;
            return false;
        } else {
            options.paths.push_back(fs::path(arg));
        }
    }
    if (options.paths.empty()) {
        error = "at least one path is required";
        return false;
    }
    return true;
}

std::vector<Rule> build_rules() {
    const std::regex::flag_type flags = std::regex::ECMAScript;
    std::vector<Rule> rules;
    rules.push_back({"aws-access-key", "AWS access key", Severity::High,
                     std::regex("AKIA[0-9A-Z]{16}", flags)});
    rules.push_back({"github-token", "GitHub token", Severity::High,
                     std::regex("gh[pousr]_[A-Za-z0-9]{36,}", flags)});
    rules.push_back({"slack-token", "Slack token", Severity::High,
                     std::regex("xox[baprs]-[A-Za-z0-9-]{10,}", flags)});
    rules.push_back({"stripe-live-key", "Stripe live key", Severity::High,
                     std::regex("sk_live_[A-Za-z0-9]{16,}", flags)});
    rules.push_back({"private-key-pem", "Private key PEM", Severity::High,
                     std::regex("-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY", flags)});
    rules.push_back({"google-api-key", "Google API key", Severity::High,
                     std::regex("AIza[0-9A-Za-z_-]{35}", flags)});
    rules.push_back({"npm-token", "npm token", Severity::High,
                     std::regex("npm_[A-Za-z0-9]{36}", flags)});
    rules.push_back({"jwt", "JWT", Severity::Medium,
                     std::regex("eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{5,}", flags)});
    return rules;
}

bool is_skipped_directory_name(const fs::path &path) {
    const std::string name = path.filename().string();
    static const char *const skipped[] = {
        ".git", "node_modules", "vendor", "dist", "build",
        "target", "__pycache__", ".venv", "venv"};
    for (const char *entry : skipped) {
        if (name == entry) {
            return true;
        }
    }
    return false;
}

std::string to_lower_ascii(std::string text) {
    for (char &ch : text) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return text;
}

bool contains_placeholder(const std::string &value) {
    const std::string lower = to_lower_ascii(value);
    static const char *const placeholders[] = {
        "example", "changeme", "placeholder", "xxxx", "your_", "<", ">", "${", "%s"};
    for (const char *placeholder : placeholders) {
        if (lower.find(placeholder) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string redact(const std::string &text) {
    if (text.size() <= 10U) {
        return text;
    }
    return text.substr(0U, 6U) + "\xE2\x80\xA6" + text.substr(text.size() - 4U);
}

std::string json_escape(const std::string &text) {
    std::ostringstream out;
    for (unsigned char ch : text) {
        switch (ch) {
        case '"':
            out << "\\\"";
            break;
        case '\\':
            out << "\\\\";
            break;
        case '\b':
            out << "\\b";
            break;
        case '\f':
            out << "\\f";
            break;
        case '\n':
            out << "\\n";
            break;
        case '\r':
            out << "\\r";
            break;
        case '\t':
            out << "\\t";
            break;
        default:
            if (ch < 0x20U) {
                static const char digits[] = "0123456789abcdef";
                out << "\\u00" << digits[(ch >> 4U) & 0x0FU] << digits[ch & 0x0FU];
            } else {
                out << static_cast<char>(ch);
            }
            break;
        }
    }
    return out.str();
}

void add_finding(ScanResult &result,
                 const std::string &rule,
                 Severity severity,
                 const std::string &path,
                 std::size_t line,
                 const std::string &match) {
    Finding finding;
    finding.rule = rule;
    finding.severity = severity;
    finding.path = path;
    finding.line = line;
    finding.redacted = redact(match);
    result.findings.push_back(finding);
    if (severity == Severity::High) {
        ++result.stats.high;
    } else if (severity == Severity::Medium) {
        ++result.stats.medium;
    } else {
        ++result.stats.low;
    }
}

bool spans_overlap(std::size_t begin, std::size_t end, const std::vector<Span> &spans) {
    for (const Span &span : spans) {
        if (begin < span.end && end > span.begin) {
            return true;
        }
    }
    return false;
}

bool is_binary_file(const fs::path &path, bool &io_error) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        io_error = true;
        return false;
    }
    char buffer[4096];
    input.read(buffer, sizeof(buffer));
    const std::streamsize read_count = input.gcount();
    for (std::streamsize i = 0; i < read_count; ++i) {
        if (buffer[static_cast<std::size_t>(i)] == '\0') {
            return true;
        }
    }
    return false;
}

bool read_file(const fs::path &path, std::uintmax_t size, std::string &content) {
    if (size > static_cast<std::uintmax_t>(std::numeric_limits<std::size_t>::max()) ||
        size > static_cast<std::uintmax_t>(std::numeric_limits<std::streamsize>::max())) {
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return false;
    }
    content.resize(static_cast<std::size_t>(size));
    if (!content.empty()) {
        input.read(&content[0], static_cast<std::streamsize>(content.size()));
        if (input.gcount() != static_cast<std::streamsize>(content.size())) {
            return false;
        }
    }
    return true;
}

bool should_skip_entropy_line(const std::string &path, const std::string &line) {
    const std::string lower_path = to_lower_ascii(path);
    const std::string lower_line = to_lower_ascii(line);
    if (lower_path.size() >= 5U && lower_path.compare(lower_path.size() - 5U, 5U, ".lock") == 0) {
        return true;
    }
    if (lower_path.size() >= 10U && lower_path.compare(lower_path.size() - 10U, 10U, "-lock.json") == 0) {
        return true;
    }
    if (lower_path.size() >= 4U && lower_path.compare(lower_path.size() - 4U, 4U, ".sum") == 0) {
        return true;
    }
    return lower_line.find("integrity") != std::string::npos ||
           lower_line.find("sha512-") != std::string::npos;
}

bool is_token_char(char ch) {
    return (ch >= 'A' && ch <= 'Z') ||
           (ch >= 'a' && ch <= 'z') ||
           (ch >= '0' && ch <= '9') ||
           ch == '+' || ch == '/' || ch == '=' || ch == '_' || ch == '-';
}

double shannon_entropy(const std::string &token) {
    int counts[256] = {};
    for (unsigned char ch : token) {
        ++counts[ch];
    }
    double entropy = 0.0;
    const double length = static_cast<double>(token.size());
    for (int count : counts) {
        if (count > 0) {
            const double probability = static_cast<double>(count) / length;
            entropy -= probability * std::log2(probability);
        }
    }
    return entropy;
}

bool has_digit_and_mixed_case(const std::string &token) {
    bool digit = false;
    bool lower = false;
    bool upper = false;
    for (char ch : token) {
        if (ch >= '0' && ch <= '9') {
            digit = true;
        } else if (ch >= 'a' && ch <= 'z') {
            lower = true;
        } else if (ch >= 'A' && ch <= 'Z') {
            upper = true;
        }
    }
    return digit && lower && upper;
}

void scan_entropy_line(ScanResult &result,
                       const std::string &path,
                       const std::string &line,
                       std::size_t line_number,
                       const std::vector<Span> &covered_spans) {
    if (should_skip_entropy_line(path, line)) {
        return;
    }

    std::size_t index = 0;
    while (index < line.size()) {
        while (index < line.size() && !is_token_char(line[index])) {
            ++index;
        }
        const std::size_t begin = index;
        while (index < line.size() && is_token_char(line[index])) {
            ++index;
        }
        const std::size_t end = index;
        const std::size_t length = end - begin;
        if (length >= 24U && length <= 128U && !spans_overlap(begin, end, covered_spans)) {
            const std::string token = line.substr(begin, length);
            if (has_digit_and_mixed_case(token) && shannon_entropy(token) > 4.5) {
                add_finding(result, "high-entropy-token", Severity::Low, path, line_number, token);
            }
        }
    }
}

void scan_line(ScanResult &result,
               const std::vector<Rule> &rules,
               const Options &options,
               const std::string &path,
               const std::string &line,
               std::size_t line_number) {
    std::vector<Span> covered_spans;
    for (const Rule &rule : rules) {
        std::sregex_iterator it(line.begin(), line.end(), rule.pattern);
        const std::sregex_iterator end;
        for (; it != end; ++it) {
            const std::smatch match = *it;
            const std::size_t begin = static_cast<std::size_t>(match.position(0));
            const std::size_t length = static_cast<std::size_t>(match.length(0));
            covered_spans.push_back({begin, begin + length});
            add_finding(result, rule.id, rule.severity, path, line_number, match.str(0));
        }
    }

    static const std::regex assignment_pattern(
        "\\b(api_key|apikey|secret|token|passwd|password|auth)\\b[ \\t]*[=:][ \\t]*([\"'])([^\"']{12,})\\2",
        std::regex::ECMAScript | std::regex::icase);
    std::sregex_iterator assignment_it(line.begin(), line.end(), assignment_pattern);
    const std::sregex_iterator assignment_end;
    for (; assignment_it != assignment_end; ++assignment_it) {
        const std::smatch match = *assignment_it;
        const std::string value = match.str(3);
        const std::size_t begin = static_cast<std::size_t>(match.position(3));
        const std::size_t length = static_cast<std::size_t>(match.length(3));
        // a value already matched by a specific pattern rule is reported once,
        // under the more precise rule
        if (!contains_placeholder(value) && !spans_overlap(begin, begin + length, covered_spans)) {
            covered_spans.push_back({begin, begin + length});
            add_finding(result, "generic-assignment", Severity::Medium, path, line_number, value);
        }
    }

    if (options.entropy) {
        scan_entropy_line(result, path, line, line_number, covered_spans);
    }
}

void scan_content(ScanResult &result,
                  const std::vector<Rule> &rules,
                  const Options &options,
                  const std::string &path,
                  const std::string &content) {
    std::size_t line_number = 1;
    std::size_t begin = 0;
    while (begin <= content.size()) {
        std::size_t end = content.find('\n', begin);
        if (end == std::string::npos) {
            end = content.size();
        }
        std::string line = content.substr(begin, end - begin);
        if (!line.empty() && line[line.size() - 1U] == '\r') {
            line.erase(line.size() - 1U);
        }
        scan_line(result, rules, options, path, line, line_number);
        if (end == content.size()) {
            break;
        }
        begin = end + 1U;
        ++line_number;
    }
}

void scan_file(ScanResult &result,
               const std::vector<Rule> &rules,
               const Options &options,
               const fs::path &path) {
    std::error_code ec;
    const std::uintmax_t size = fs::file_size(path, ec);
    if (ec) {
        result.io_error = true;
        return;
    }
    if (size > options.max_size) {
        ++result.stats.files_skipped;
        return;
    }

    bool binary_io_error = false;
    if (is_binary_file(path, binary_io_error)) {
        ++result.stats.files_skipped;
        return;
    }
    if (binary_io_error) {
        result.io_error = true;
        return;
    }

    std::string content;
    if (!read_file(path, size, content)) {
        result.io_error = true;
        return;
    }
    ++result.stats.files_scanned;
    scan_content(result, rules, options, path.string(), content);
}

void scan_path(ScanResult &result,
               const std::vector<Rule> &rules,
               const Options &options,
               const fs::path &path) {
    std::error_code ec;
    const fs::file_status status = fs::status(path, ec);
    if (ec || !fs::exists(status)) {
        result.io_error = true;
        return;
    }

    if (fs::is_regular_file(status)) {
        scan_file(result, rules, options, path);
        return;
    }

    if (!fs::is_directory(status)) {
        ++result.stats.files_skipped;
        return;
    }

    fs::recursive_directory_iterator it(path, fs::directory_options::skip_permission_denied, ec);
    if (ec) {
        result.io_error = true;
        return;
    }
    const fs::recursive_directory_iterator end;
    for (; it != end; it.increment(ec)) {
        if (ec) {
            result.io_error = true;
            ec.clear();
            continue;
        }

        const fs::path current = it->path();
        std::error_code status_ec;
        const fs::file_status current_status = it->symlink_status(status_ec);
        if (status_ec) {
            result.io_error = true;
            continue;
        }

        if (fs::is_directory(current_status)) {
            if (is_skipped_directory_name(current)) {
                it.disable_recursion_pending();
            }
            continue;
        }
        if (fs::is_regular_file(current_status)) {
            scan_file(result, rules, options, current);
        } else {
            ++result.stats.files_skipped;
        }
    }
}

void print_json(const ScanResult &result) {
    std::cout << "{\"version\":1,\"findings\":[";
    for (std::size_t i = 0; i < result.findings.size(); ++i) {
        const Finding &finding = result.findings[i];
        if (i != 0U) {
            std::cout << ",";
        }
        std::cout << "{\"rule\":\"" << json_escape(finding.rule)
                  << "\",\"severity\":\"" << severity_to_string(finding.severity)
                  << "\",\"path\":\"" << json_escape(finding.path)
                  << "\",\"line\":" << finding.line
                  << ",\"redacted\":\"" << json_escape(finding.redacted) << "\"}";
    }
    std::cout << "],\"stats\":{"
              << "\"files_scanned\":" << result.stats.files_scanned
              << ",\"files_skipped\":" << result.stats.files_skipped
              << ",\"findings_high\":" << result.stats.high
              << ",\"findings_medium\":" << result.stats.medium
              << ",\"findings_low\":" << result.stats.low
              << ",\"duration_ms\":" << result.stats.duration_ms
              << "}}\n";
}

void print_console(const ScanResult &result, bool quiet) {
    const bool color = stdout_is_tty();
    if (color) {
        enable_ansi_if_possible();
    }

    if (!quiet) {
        for (const Finding &finding : result.findings) {
            if (color) {
                std::cout << severity_color(finding.severity);
            }
            std::cout << severity_to_string(finding.severity);
            if (color) {
                std::cout << "\033[0m";
            }
            std::cout << " " << finding.rule << " " << finding.path << ":"
                      << finding.line << "  " << finding.redacted << "\n";
        }
    }

    std::cout << "Summary: files scanned=" << result.stats.files_scanned
              << ", files skipped=" << result.stats.files_skipped
              << ", HIGH=" << result.stats.high
              << ", MEDIUM=" << result.stats.medium
              << ", LOW=" << result.stats.low
              << ", wall time=" << result.stats.duration_ms << "ms\n";
}

} // namespace

int main(int argc, char **argv) {
    Options options;
    bool help = false;
    std::string error;
    if (!parse_args(argc, argv, options, help, error)) {
        std::cerr << "error: " << error << "\n" << usage();
        return 2;
    }
    if (help) {
        std::cout << usage();
        return 0;
    }

    const std::vector<Rule> rules = build_rules();
    ScanResult result;
    const auto start = std::chrono::steady_clock::now();
    for (const fs::path &path : options.paths) {
        scan_path(result, rules, options, path);
    }
    const auto finish = std::chrono::steady_clock::now();
    result.stats.duration_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(finish - start).count();

    if (options.json) {
        print_json(result);
    } else {
        print_console(result, options.quiet);
    }

    if (result.io_error) {
        return 2;
    }
    return result.findings.empty() ? 0 : 1;
}
