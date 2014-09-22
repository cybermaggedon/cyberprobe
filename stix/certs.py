
from OpenSSL.crypto import X509, PKey, X509Name, X509Req, X509Extension
from OpenSSL.crypto import dump_privatekey, dump_certificate
from OpenSSL.crypto import dump_certificate_request, sign, verify
from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM

ca_key = PKey()
ca_key.generate_key(TYPE_RSA, 2048)

f = open("CA.key", "w")
f.write(dump_privatekey(FILETYPE_PEM, ca_key))
f.close()

ca = X509()

ca.get_subject().commonName = "Bunchy McX"
ca.get_subject().emailAddress = "bunchy@filigree.org"

ca.set_serial_number(1)
ca.gmtime_adj_notBefore(0)
ca.gmtime_adj_notAfter(10*365*24*60*60)

ca.set_issuer(ca.get_subject())

ca.set_pubkey(ca_key)

ca.add_extensions([
    X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
    X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
    X509Extension("subjectKeyIdentifier", False, "hash", subject=ca)
])

ca.add_extensions([
    X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
])

f = open("CA.cert", "w")
f.write(dump_certificate(FILETYPE_PEM, ca))
f.close()

host_key = PKey()
host_key.generate_key(TYPE_RSA, 2048)

f = open("HOST.key", "w")
f.write(dump_privatekey(FILETYPE_PEM, host_key))
f.close()

host_req = X509Req()
host_req.get_subject().commonName = "malware.org"
host_req.get_subject().emailAddress = "admin@malware.org"
host_req.set_pubkey(host_key)
host_req.sign(host_key, "sha1")

f = open("HOST.req", "w")
f.write(dump_certificate_request(FILETYPE_PEM, host_req))
f.close()

host = X509()
host.set_subject(host_req.get_subject())
host.set_serial_number(2)
host.gmtime_adj_notBefore(0)
host.gmtime_adj_notAfter(10*365*24*60*60)
host.set_issuer(ca.get_subject())
host.set_pubkey(host_req.get_pubkey())

host.add_extensions([
     X509Extension("basicConstraints", True, "CA:FALSE"),
     X509Extension("keyUsage", True, "digitalSignature, nonRepudiation"),
     X509Extension("extendedKeyUsage", True, "serverAuth, clientAuth"),
     X509Extension("subjectAltName", False, "DNS:malware.org"),
     X509Extension("subjectKeyIdentifier", False, "hash", subject=host)
])

host.add_extensions([
    X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
])

host.sign(ca_key, "sha1")

f = open("HOST.cert", "w")
f.write(dump_certificate(FILETYPE_PEM, host))
f.close()

#name = X509Name("asd")

#openssl verify -CAfile CA.cert HOST.cert

data = "Hello world\n"

signed_msg = sign(host_key, data, "sha1")

#signed_msg = 'a' + signed_msg[1:len(signed_msg)]

#print signed_msg

verify(host, signed_msg, data, "sha1")


