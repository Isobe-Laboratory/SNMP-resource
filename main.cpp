//
// Created by HASHIBA Keishi on 25/06/23.
//

#include <curl/curl.h>
#include <sstream>
#include <unordered_map>
#include <unistd.h>
#include <fstream>
#include <map>
#include <variant>
#include <iostream>
#include <iomanip>
#include <cmath>
#include <vector>
#include <regex>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

using json = nlohmann::json;

extern "C" {
  #include <net-snmp/net-snmp-config.h>
  #include <net-snmp/net-snmp-includes.h>
}

class SNMPException : public std::exception {
public:
    explicit SNMPException(const std::string& message)
        : msg_(message) {}

    const char* what() const noexcept override {
        return msg_.c_str();
    }

private:
    std::string msg_;
};

namespace SNMP_OID {

    enum class STR {
        HOST_NAME,
    };

    enum class NUM {
        MEM_TOTAL,
        MEM_AVIL,
        MEM_BUF,
        MEM_CACHE,
        CPU_USER,
        CPU_SYS,
        CPU_IDLE,
    };

    using OID = std::variant<STR, NUM>;

    inline const std::unordered_map<OID, const std::string> OID_MAP = {
        {STR::HOST_NAME, ".1.3.6.1.2.1.1.5.0"},
        {NUM::MEM_TOTAL, ".1.3.6.1.4.1.2021.4.5.0"},
        {NUM::MEM_AVIL,  ".1.3.6.1.4.1.2021.4.6.0"},
        {NUM::MEM_BUF,   ".1.3.6.1.4.1.2021.4.14.0"},
        {NUM::MEM_CACHE, ".1.3.6.1.4.1.2021.4.15.0"},
        {NUM::CPU_USER,  ".1.3.6.1.4.1.2021.11.9.0"},
        {NUM::CPU_SYS,   ".1.3.6.1.4.1.2021.11.10.0"},
        {NUM::CPU_IDLE,  ".1.3.6.1.4.1.2021.11.11.0"},
    };
}

struct Node {
    std::string ip_address;
};

std::vector<YAML::Node> load_yaml(const std::string& filename) {

    std::vector<YAML::Node> nodes;
    YAML::Node yaml_root = YAML::LoadFile(filename);

    for (const auto& entry : yaml_root) {
        nodes.push_back(entry["node"]);
    }
    return nodes;
}

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

void print_json(const std::string& raw_response) {
    try {
        json parsed = json::parse(raw_response);
        std::cout << parsed.dump(4) << std::endl;  // インデント付き出力
    } catch (json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
    }
}

const std::string snmp_get(const std::string& ip_address, const SNMP_OID::OID oid_num) {

    // GET OID
    auto oid_it = SNMP_OID::OID_MAP.find(oid_num);
    if (oid_it == SNMP_OID::OID_MAP.end()) {
        throw std::invalid_argument("Given OID not found");
    }
    std::string oid_str = oid_it->second;

    // SET CONNECTION
    static const char* community = std::getenv("SNMP_COMMUNITY");
    init_snmp("snmpapp");
    snmp_session session;
    snmp_sess_init(&session);
    session.peername = strdup(ip_address.c_str());
    session.version = SNMP_VERSION_2c;
    session.community = (u_char*)strdup(community);
    session.community_len = strlen(community);

    SOCK_STARTUP;
    snmp_session* ss = snmp_open(&session);
    if (!ss) {
        SOCK_CLEANUP;
        throw SNMPException("Failed to open SNMP session");
    }

    netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_GET);

    // GET VALUES
    oid anOID[MAX_OID_LEN];
    size_t anOID_len = MAX_OID_LEN;
    if (!read_objid(oid_str.c_str(), anOID, &anOID_len)) {
        snmp_close(ss);
        SOCK_CLEANUP;
        throw SNMPException("Invalid OID");
    }
    snmp_add_null_var(pdu, anOID, anOID_len);

    // PARSE RESPONSE
    netsnmp_pdu* response = nullptr;
    int status = snmp_synch_response(ss, pdu, &response);

    if (status != STAT_SUCCESS || !response) {
        snmp_close(ss);
        SOCK_CLEANUP;
        throw SNMPException("No response from server");
    }

    if (response->errstat != SNMP_ERR_NOERROR) {
        std::string err = snmp_errstring(response->errstat);
        snmp_free_pdu(response);
        snmp_close(ss);
        SOCK_CLEANUP;
        throw SNMPException(err.c_str());
    }

    char val_buf[1024] = {0};

    for (netsnmp_variable_list* vars = response->variables; vars; vars = vars->next_variable) {
        snprint_value(val_buf, sizeof(val_buf), vars->name, vars->name_length, vars);
        // std::cout << val_buf << std::endl;
    }

    snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;

    return std::string(val_buf);
}

int get_int(const std::string& ip_address, const SNMP_OID::NUM oid_num){
    const std::string val_str = snmp_get(ip_address, oid_num);

    int val_int = 0;
    try {
        std::size_t pos = val_str.find(":");
        if (pos == std::string::npos) {
            throw std::runtime_error("Unexpected value format: colon not found");
        }

        std::string num_str = val_str.substr(pos + 1);  // " 87568504"
        num_str.erase(0, num_str.find_first_not_of(" \t"));

        val_int = std::stoi(num_str);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }

    return val_int;
}

std::string get_str(const std::string& ip_address, const SNMP_OID::STR oid_num){
    const std::string val_str = snmp_get(ip_address, oid_num);
    std::string extracted;

    try {
        const std::string prefix = "STRING: ";
        if (val_str.compare(0, prefix.length(), prefix) != 0) {
            throw std::runtime_error("Invalid format: missing 'STRING: ' prefix");
        }

        std::string remainder = val_str.substr(prefix.length());

        if (remainder.front() != '"' || remainder.back() != '"') {
            throw std::runtime_error("Invalid format: missing enclosing double quotes");
        }

        extracted = remainder.substr(1, remainder.length() - 2);
    } catch (const std::exception& e) {
        std::cerr << "Error while parsing string: " << e.what() << std::endl;
    }

    return extracted;
}

std::string showBar(double value) {
    int blocks = std::ceil(value / 10.0);
    std::string color = value >= 90 ? "🟥" :
                        value >= 80 ? "🟧" :
                        value >= 70 ? "🟨" :
                        value >= 30 ? "🟩" :
                        value >   0 ? "🟦" : "⬜️";

    std::string bar;

    for (int i = 0; i < 10; ++i){
        bar += (i < blocks ? color : "⬜");
    }
    return bar;
}

int main(void) {

    const std::string filename = "../address_list.yaml";
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return -1;
    }
    file.close();

    std::vector<YAML::Node> nodes = load_yaml(filename);

    std::ostringstream send_text;
    send_text << "```" << std::endl;
    send_text << " IP ADDRESS      | Remark           | HOST NAME  | CPU (%)              | TOTAL MEM | MEMORY (%)                  " << std::endl;
    send_text << "-----------------+------------------+------------+----------------------+-----------+-----------------------------" << std::endl;

    // while (std::getline(file, ip_address)) {
    for (const auto& node : nodes) {
        std::string ip_address = node["ip_address"].as<std::string>();

        if(ip_address.empty() || ip_address[0] == '#'){
            continue;
        }

        /* DEBUG */ std::cout << "SNMP CONNECTING TO -> " << ip_address << std::endl;

        std::ostringstream oss_host;

        // (IP address)
        oss_host << " " << std::left << std::setw(15) << ip_address << std::right << " | ";

        // remark
        std::string remark = "";
        if(node["remark"]){
            remark = node["remark"].as<std::string>();
        }

        try{
            // HOST NAME
            std::string host_name = get_str(ip_address, SNMP_OID::STR::HOST_NAME);

            // CPU
            int cpu_user = get_int(ip_address, SNMP_OID::NUM::CPU_USER);
            int cpu_sys  = get_int(ip_address, SNMP_OID::NUM::CPU_SYS);
            int cpu_idle = get_int(ip_address, SNMP_OID::NUM::CPU_IDLE);

            int cpu_used = cpu_user + cpu_sys;


            // MEMORY
            int mem_total = get_int(ip_address, SNMP_OID::NUM::MEM_TOTAL);
            int mem_avil  = get_int(ip_address, SNMP_OID::NUM::MEM_AVIL);
            int mem_buf   = get_int(ip_address, SNMP_OID::NUM::MEM_BUF);
            int mem_cache = get_int(ip_address, SNMP_OID::NUM::MEM_CACHE);
            int mem_used = mem_total - mem_avil - mem_buf - mem_cache;
            double mem_used_percent = 100.0 * mem_used / mem_total;

            oss_host << std::setw(16) << remark;
            oss_host << " | ";

            oss_host << std::setw(10) << host_name;
            oss_host << " | ";

            oss_host << " " << std::setw(3) << cpu_used << " " << showBar(cpu_used);
            oss_host << " | ";

            oss_host << std::setw(10) << static_cast<int>(mem_total/std::pow(2, 20));
            oss_host << " | ";

            oss_host << " " << std::setw(10) << mem_used_percent << " " << showBar(mem_used_percent);
            oss_host << std::endl;

        }
        catch (const std::exception& e) {
            std::cerr << "Some error raised (target ip addr : " << ip_address << ")" << std::endl;
            std::cerr << e.what() << std::endl;
            oss_host << " ERROR" << std::endl;
        }
        send_text << oss_host.str();
    }
    send_text << "```" << std::endl;

    file.close();

    std::cout << "[DEBUG] GOT ALL INFORMATION VIA SNMP" << std::endl;

    // Slack API
    const char* token = std::getenv("SLACK_OAUTH_TOKEN");
    const char* channel = std::getenv("CHANNEL_NAME");
    const char* ts = std::getenv("SLACK_TS");
    if (!token || !channel || !ts) {
        std::cout << "[ERROR] Could not get env vars!" << std::endl;
        return 1;
    }

    // GET HISTORY
    CURL* c_get = curl_easy_init();
    if (!c_get) {
        std::cout << "[ERROR] curl has not been established!" << std::endl;
        return 1;
    }
    std::map<std::string, std::string> p_history{
        {"token", token},
        {"channel", channel},
        {"username", "SNMP"}
    };
    std::string f_history;
    std::string response;
    for (auto& [k,v] : p_history) {
        char* ek = curl_easy_escape(c_get, k.c_str(), 0);
        char* ev = curl_easy_escape(c_get, v.c_str(), 0);
        if (!f_history.empty()) f_history += '&';
        f_history += ek; f_history += '='; f_history += ev;
        curl_free(ek); curl_free(ev);
    }
    curl_easy_setopt(c_get, CURLOPT_URL, "https://slack.com/api/conversations.history");
    curl_easy_setopt(c_get, CURLOPT_POSTFIELDS, f_history.c_str());
    curl_easy_setopt(c_get, CURLOPT_WRITEFUNCTION, nullptr);
    curl_easy_setopt(c_get, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(c_get, CURLOPT_WRITEFUNCTION, WriteCallback);

    CURLcode res = curl_easy_perform(c_get);
    curl_easy_cleanup(c_get);

    json messages_json;

    if (res == CURLE_OK) {
        try {
            messages_json = json::parse(response);
        } catch (json::parse_error& e) {
            std::cerr << "JSON parse error: " << e.what() << std::endl;
        }
    } else {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    }
    std::cout << "[DEBUG] GOT ALL MESSAGES" << std::endl;

    // DELETE MESSAGES
    for (const auto& msg : messages_json["messages"]) {
        if (msg.contains("bot_id")) {
            std::string ts = msg["ts"];

            std::map<std::string, std::string> p_delete{
                {"token", token},
                {"channel", channel},
                {"ts", ts}
            };

            CURL* c_delete = curl_easy_init();
            if (!c_delete) return 1;
            std::string f_delete;
            std::string response;
            for (auto& [k,v] : p_delete) {
                char* ek = curl_easy_escape(c_delete, k.c_str(), 0);
                char* ev = curl_easy_escape(c_delete, v.c_str(), 0);
                if (!f_delete.empty()) f_delete += '&';
                f_delete += ek; f_delete += '='; f_delete += ev;
                curl_free(ek); curl_free(ev);
            }

            curl_easy_setopt(c_delete, CURLOPT_URL, "https://slack.com/api/chat.delete");
            curl_easy_setopt(c_delete, CURLOPT_POSTFIELDS, f_delete.c_str());
            curl_easy_setopt(c_delete, CURLOPT_WRITEFUNCTION, nullptr);

            curl_easy_perform(c_delete);
            curl_easy_cleanup(c_delete);
        }
    }

    std::cout << "[DEBUG] DELETED ALL MESSAGES" << std::endl;

    // UPDATE THE MESSAGES
    CURL* c_send = curl_easy_init();
    if (!c_send) return 1;

    std::map<std::string,std::string> p{
        {"token", token},
        {"channel", channel},
        {"text", send_text.str()},
        {"username", "SNMP"}
    };

    std::string f;
    for (auto& [k,v] : p) {
        char* ek = curl_easy_escape(c_send, k.c_str(), 0);
        char* ev = curl_easy_escape(c_send, v.c_str(), 0);
        if (!f.empty()) f += '&';
        f += ek; f += '='; f += ev;
        curl_free(ek); curl_free(ev);
    }

    curl_easy_setopt(c_send, CURLOPT_URL, "https://slack.com/api/chat.postMessage");
    curl_easy_setopt(c_send, CURLOPT_POSTFIELDS, f.c_str());
    curl_easy_setopt(c_send, CURLOPT_WRITEFUNCTION, nullptr);

    curl_easy_perform(c_send);
    curl_easy_cleanup(c_send);

    std::cout << send_text.str() << std::endl;

    std::cout << "[DEBUG] SEND THE MESSAGE" << std::endl;

    return 0;
}
