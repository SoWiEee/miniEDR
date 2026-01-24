#pragma once
#include <cctype>
#include <map>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace miniedr::json {

// Minimal JSON value type (enough for rulesets).
// Supported: null, bool, number (double), string, array, object.
struct Value;
using Array = std::vector<Value>;
using Object = std::map<std::string, Value>;

struct Value {
    using Storage = std::variant<std::nullptr_t, bool, double, std::string, Array, Object>;
    Storage v;

    Value() : v(nullptr) {}
    Value(std::nullptr_t) : v(nullptr) {}
    Value(bool b) : v(b) {}
    Value(double d) : v(d) {}
    Value(std::string s) : v(std::move(s)) {}
    Value(Array a) : v(std::move(a)) {}
    Value(Object o) : v(std::move(o)) {}

    bool is_null() const { return std::holds_alternative<std::nullptr_t>(v); }
    bool is_bool() const { return std::holds_alternative<bool>(v); }
    bool is_number() const { return std::holds_alternative<double>(v); }
    bool is_string() const { return std::holds_alternative<std::string>(v); }
    bool is_array() const { return std::holds_alternative<Array>(v); }
    bool is_object() const { return std::holds_alternative<Object>(v); }

    const bool& as_bool() const { return std::get<bool>(v); }
    const double& as_number() const { return std::get<double>(v); }
    const std::string& as_string() const { return std::get<std::string>(v); }
    const Array& as_array() const { return std::get<Array>(v); }
    const Object& as_object() const { return std::get<Object>(v); }

    const Value* get(const std::string& key) const {
        if (!is_object()) return nullptr;
        const auto& o = as_object();
        auto it = o.find(key);
        return (it == o.end()) ? nullptr : &it->second;
    }
};

class Parser {
public:
    explicit Parser(const std::string& s) : s_(s) {}

    Value parse() {
        skip_ws();
        Value out = parse_value();
        skip_ws();
        if (i_ != s_.size()) throw std::runtime_error("Trailing data after JSON document");
        return out;
    }

private:
    const std::string& s_;
    size_t i_ = 0;

    void skip_ws() {
        while (i_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[i_]))) i_++;
    }

    char peek() const { return (i_ < s_.size()) ? s_[i_] : '\0'; }

    char getc() {
        if (i_ >= s_.size()) throw std::runtime_error("Unexpected EOF");
        return s_[i_++];
    }

    bool consume(char c) {
        if (peek() == c) { i_++; return true; }
        return false;
    }

    Value parse_value() {
        skip_ws();
        char c = peek();
        if (c == '"') return Value(parse_string());
        if (c == '{') return Value(parse_object());
        if (c == '[') return Value(parse_array());
        if (c == 't') { expect("true"); return Value(true); }
        if (c == 'f') { expect("false"); return Value(false); }
        if (c == 'n') { expect("null"); return Value(nullptr); }
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return Value(parse_number());
        throw std::runtime_error("Invalid JSON value");
    }

    void expect(const char* lit) {
        for (const char* p = lit; *p; ++p) {
            if (getc() != *p) throw std::runtime_error(std::string("Expected literal: ") + lit);
        }
    }

    std::string parse_string() {
        if (getc() != '"') throw std::runtime_error("Expected '\"'");
        std::string out;
        while (true) {
            char c = getc();
            if (c == '"') break;
            if (c == '\\') {
                char e = getc();
                switch (e) {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    // Minimal \uXXXX support (BMP only).
                    unsigned code = 0;
                    for (int k = 0; k < 4; k++) {
                        char h = getc();
                        code <<= 4;
                        if (h >= '0' && h <= '9') code |= (h - '0');
                        else if (h >= 'a' && h <= 'f') code |= (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') code |= (h - 'A' + 10);
                        else throw std::runtime_error("Invalid \\uXXXX escape");
                    }
                    // Encode as UTF-8 (BMP only).
                    if (code <= 0x7F) out.push_back(static_cast<char>(code));
                    else if (code <= 0x7FF) {
                        out.push_back(static_cast<char>(0xC0 | ((code >> 6) & 0x1F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    } else {
                        out.push_back(static_cast<char>(0xE0 | ((code >> 12) & 0x0F)));
                        out.push_back(static_cast<char>(0x80 | ((code >> 6) & 0x3F)));
                        out.push_back(static_cast<char>(0x80 | (code & 0x3F)));
                    }
                    break;
                }
                default:
                    throw std::runtime_error("Invalid escape sequence");
                }
            } else {
                out.push_back(c);
            }
        }
        return out;
    }

    double parse_number() {
        size_t start = i_;
        if (consume('-')) {}
        if (consume('0')) {
            // ok
        } else {
            if (!std::isdigit(static_cast<unsigned char>(peek()))) throw std::runtime_error("Invalid number");
            while (std::isdigit(static_cast<unsigned char>(peek()))) i_++;
        }
        if (consume('.')) {
            if (!std::isdigit(static_cast<unsigned char>(peek()))) throw std::runtime_error("Invalid number fraction");
            while (std::isdigit(static_cast<unsigned char>(peek()))) i_++;
        }
        if (peek() == 'e' || peek() == 'E') {
            i_++;
            if (peek() == '+' || peek() == '-') i_++;
            if (!std::isdigit(static_cast<unsigned char>(peek()))) throw std::runtime_error("Invalid number exponent");
            while (std::isdigit(static_cast<unsigned char>(peek()))) i_++;
        }
        return std::stod(s_.substr(start, i_ - start));
    }

    Array parse_array() {
        if (getc() != '[') throw std::runtime_error("Expected '['");
        Array arr;
        skip_ws();
        if (consume(']')) return arr;
        while (true) {
            arr.push_back(parse_value());
            skip_ws();
            if (consume(']')) break;
            if (!consume(',')) throw std::runtime_error("Expected ',' in array");
        }
        return arr;
    }

    Object parse_object() {
        if (getc() != '{') throw std::runtime_error("Expected '{'");
        Object obj;
        skip_ws();
        if (consume('}')) return obj;
        while (true) {
            skip_ws();
            std::string key = parse_string();
            skip_ws();
            if (!consume(':')) throw std::runtime_error("Expected ':' in object");
            Value val = parse_value();
            obj.emplace(std::move(key), std::move(val));
            skip_ws();
            if (consume('}')) break;
            if (!consume(',')) throw std::runtime_error("Expected ',' in object");
        }
        return obj;
    }
};

inline Value parse(const std::string& s) {
    return Parser(s).parse();
}

} // namespace miniedr::json
