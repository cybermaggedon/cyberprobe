
#ifndef TLS_EXTENSIONS_H
#define TLS_EXTENSIONS_H

namespace cybermon {
namespace tls_extensions {

std::vector<std::string> lookupExts = {
    "server_name",
    "max_fragment_length",
    "client_certificate_url",
    "trusted_ca_keys",
    "truncated_hmac",
    "status_request",
    "user_mapping",
    "client_authz",
    "server_authz",
    "cert_type",
    "supported_groups",
    "ec_point_formats",
    "srp",
    "signature_algorithms",
    "use_srtp",
    "heartbeat",
    "application_layer_protocol_negotiation",
    "status_request_v2",
    "signed_certificate_timestamp",
    "client_certificate_type",
    "server_certificate_type",
    "padding",
    "encrypt_then_mac",
    "extended_master_secret",
    "token_binding",
    "cached_info",
    "tls_lts",
    "compress_certificate",
    "record_size_limit",
    "pwd_protect",
    "pwd_clear",
    "password_salt",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "session_ticket",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "Unassigned",
    "pre_shared_key",
    "early_data",
    "supported_versions",
    "cookie",
    "psk_key_exchange_modes",
    "Unassigned",
    "certificate_authorities",
    "oid_filters",
    "post_handshake_auth",
    "signature_algorithms_cert",
    "key_share",
    "transparency_info"
};

static std::string lookup(uint16_t id) {
    if (id <= 53)
    {
        return lookupExts[id];
    }
    else if (id <= 65279)
    {
        return "Unassigned";
    }
    else if (id == 65280 || id >= 65282)
    {
        return "Reserved";
    }
    else
    {
        return "renegotiation_info";
    }

}
}
}



#endif
