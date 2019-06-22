
#include <cybermon/event.h>
#include <cybermon/engine.h>

using namespace cybermon::event;

std::string protocol_event::get_device() {
    std::string device;
    address trigger_address;
    cybermon::engine::get_root_info(context, device, trigger_address);
    return device;
}

std::string action_names[] = {
    "connection_up",
    "connection_down",
    "trigger_up",
    "trigger_down",
    "unrecognised_stream",
    "unrecognised_datagram",
    "icmp",
    "imap",
    "imap_ssl",
    "pop3",
    "pop3_ssl",
    "rtp",
    "rtp_ssl",
    "sip_request",
    "sip_response",
    "sip_ssl",
    "smtp_auth",
    "smtp_command",
    "smtp_response",
    "smtp_data",
    "http_request",
    "http_response",
    "ftp_command",
    "ftp_response",
    "dns_message",
    "ntp_timestamp_message",
    "ntp_control_message",
    "ntp_private_message",
    "gre_message",
    "gre_pptp_message",
    "esp",
    "unrecognised_ip_protocol",
    "wlan",
    "tls_unknown",
    "tls_client_hello",
    "tls_server_hello",
    "tls_certificates",
    "tls_server_key_exchange",
    "tls_server_hello_done",
    "tls_handshake_generic",
    "tls_certificate_request",
    "tls_client_key_exchange",
    "tls_certificate_verify",
    "tls_change_cipher_spec",
    "tls_handshake_finished",
    "tls_handshake_complete",
    "tls_application_data"
};

std::string& cybermon::event::action2string(action_type a)
{
    return action_names[a];
}
