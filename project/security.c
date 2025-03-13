#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Global Variables:

#define CLIENT_HELLO_SIZE 256
uint8_t client_hello_buf[CLIENT_HELLO_SIZE];
uint16_t client_hello_length = 0;
#define SERVER_HELLO_SIZE 1024
uint8_t server_hello_buf[SERVER_HELLO_SIZE];
uint16_t server_hello_length = 0;

// flags
int8_t client_hello_sent = 0;
int8_t client_hello_recvd = 0;
int8_t server_hello_sent = 0;
int8_t server_hello_recvd = 0;
int8_t client_finished_sent = 0;
int8_t client_finished_recvd = 0;

int host_type = -1;
char host_name[256] = "";



void init_sec(int type, char* host) {
    init_io();
    host_type = type;
    
    if (host != NULL)
        memcpy(host_name, host, strlen(host) + 1);

    fprintf(stderr, "Type = %d, Hostname: %s\n", host_type, host_name);
    
}

// Transport layers call this when making packets!
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    
    // CLIENT: client hello
    if (host_type == CLIENT && !client_hello_sent) {

        fprintf(stderr, "Client creating client_hello!\n");

        // 1. Generate a public / private key pair
        generate_private_key();
        derive_public_key();

        // 2. Server Hello
        tlv* ch = create_tlv(CLIENT_HELLO);

        // 3. nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);

        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        // 4. public key
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        uint16_t len = serialize_tlv(buf, ch);
        free_tlv(ch);

        // 5. Cache client_hello for signature
        memcpy(client_hello_buf, buf, len);
        client_hello_length = len;
        client_hello_sent = 1;

        return len;
    }
    
    // CLIENT: client finished
    else if (host_type == CLIENT && !client_finished_sent) {
        
        fprintf(stderr, "Finished Client sent!\n");

        tlv* finished_msg_tlv = create_tlv(FINISHED);

        tlv* ch_tmp = deserialize_tlv(client_hello_buf, client_hello_length);
        tlv* sh_tmp = deserialize_tlv(server_hello_buf, server_hello_length);

        uint8_t transcript_buf[2048];
        uint8_t hmac_buf[32];

        uint16_t transcript_len = 0;

        transcript_len += serialize_tlv(transcript_buf + transcript_len, ch_tmp);
        transcript_len += serialize_tlv(transcript_buf + transcript_len, sh_tmp);

        uint16_t len = 0;

        fprintf(stderr, "Transcript Length: %d\n", transcript_len);
        
        hmac(hmac_buf, transcript_buf, transcript_len);

        tlv* transcript_tlv = create_tlv(TRANSCRIPT);
        add_val(transcript_tlv, hmac_buf, 32);
        add_tlv(finished_msg_tlv, transcript_tlv);

        len = serialize_tlv(buf, finished_msg_tlv);
        fprintf(stderr, "Got here!\n");

        free_tlv(transcript_tlv);
        free_tlv(ch_tmp);
        free_tlv(sh_tmp);
        client_finished_sent = 1;

        fprintf(stderr, "Got here! - serialized\n");

        return len;
    }

    // SERVER: server hello
    if (host_type == SERVER && client_hello_recvd && !server_hello_sent) {
        
        fprintf(stderr, "\nServer Creating TLV!\n");
        
        tlv* sh = create_tlv(SERVER_HELLO);
        
        // 1. Generate a nonce
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);

        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(sh, nn);

        // 2. Copy certificate into server-hello
        load_certificate("server_cert.bin");
        tlv* cert = create_tlv(CERTIFICATE);
        add_val(cert, certificate, cert_size);
        add_tlv(sh, cert);   

        // 3. Generate a public / private key: Ephemeral - one time use
        load_private_key("server_key.bin");
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(sh, pk);

        // 4. Create hand-shake signature
        uint8_t signature_buf[1024];
        uint16_t signature_buf_len = 0;

        tlv* ch = deserialize_tlv(client_hello_buf, client_hello_length);
        fprintf(stderr, "Client Hello inside server!\n");

        // print_tlv_bytes(ch, client_hello_length);

        signature_buf_len += serialize_tlv(signature_buf + signature_buf_len, ch);
        signature_buf_len += serialize_tlv(signature_buf + signature_buf_len, nn);
        signature_buf_len += serialize_tlv(signature_buf + signature_buf_len, cert);
        signature_buf_len += serialize_tlv(signature_buf + signature_buf_len, pk);

        uint8_t signature[72]; // max length 72 bytes
        int32_t signature_len = 0;

        signature_len = sign(signature, signature_buf, signature_buf_len);  
        
        tlv* sig = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig, signature, signature_len);
        add_tlv(sh, sig);   

        uint16_t len = serialize_tlv(buf, sh);
        free_tlv(sh);

        // 5. Cache server hello
        memcpy(server_hello_buf, buf, len);
        server_hello_length = len;
        server_hello_sent = 1;
    
        //6. Derive shared secret

        tlv* client_public_key = get_tlv(ch, PUBLIC_KEY);
        load_peer_public_key(client_public_key->val, client_public_key->length);
        derive_secret();

        uint8_t salt_buf[2048];
        uint16_t salt_buf_len = 0;
        
        tlv* ch_tmp = deserialize_tlv(client_hello_buf, client_hello_length);
        tlv* sh_tmp = deserialize_tlv(server_hello_buf, server_hello_length);

        salt_buf_len += serialize_tlv(salt_buf + salt_buf_len, ch_tmp);
        salt_buf_len += serialize_tlv(salt_buf + salt_buf_len, sh_tmp);

        fprintf(stderr, "DERIVED SHARED KEYS!\n");
        derive_keys(salt_buf, salt_buf_len);

        return len;
    }

    return input_io(buf, max_length);
}

// Each time Transport layer receives in-order packet it will call this
void output_sec(uint8_t* buf, size_t length) {
    
    tlv* sh = deserialize_tlv(buf, length);

    if (sh != NULL) {

        // CLIENT: client finish - receive server hello
        if (host_type == CLIENT && client_hello_sent && !server_hello_recvd) {
            
            fprintf(stderr, "SERVER HELLO RECEIVED \n");

            // 1. Verify CA Certificate
            load_certificate("server_cert.bin");
            load_ca_public_key("ca_public_key.bin"); // GENERATES uint8_t* GLOBAL VARIABLES: certificate and size_t cert_size
            tlv* cert = deserialize_tlv(certificate, cert_size);

            fprintf(stderr, "Certificate Type: 0x%x\n", cert->type);

            tlv* dns = get_tlv(cert, DNS_NAME);
            tlv* ca_pk = get_tlv(cert, PUBLIC_KEY);
            
            tlv* ca_sig = get_tlv(cert, SIGNATURE);

            // signature ! 
            uint8_t certificate_buffer[1024];
            uint16_t certificate_buffer_len = 0;

            certificate_buffer_len += serialize_tlv(certificate_buffer + certificate_buffer_len, dns);
            certificate_buffer_len += serialize_tlv(certificate_buffer + certificate_buffer_len, ca_pk);

            
            if (verify(ca_sig->val, ca_sig->length, certificate_buffer, certificate_buffer_len, ec_ca_public_key) == 1) {
                fprintf(stderr, "WERE SO BACK - VERIFIED THE CERTIFICATE\n");
            }
            else 
            {
                fprintf(stderr, "Uh oh\n\n\n");
                exit(1);
            }

            // 2. Verify DNS name with what was passed to clients arguements:
            fprintf(stderr, "Type = %d, Hostname: %s\n", host_type, host_name);

            if (strcmp(host_name, (char*)dns->val) == 0) {
                fprintf(stderr, "WERE SO BACK - VERIFIED DNS NAME\n");
            }
            else 
            {
                fprintf(stderr, "Uh oh\n\n\n");
                exit(2);
            }

            // 3. Verifiy the server hello was signed by the server
            tlv* sig = get_tlv(sh, HANDSHAKE_SIGNATURE);

            fprintf(stderr, "Printing signature type\n");
            fprintf(stderr, "0x%x\n", sig->type);

            // use cached client hello
            tlv* ch_sig = deserialize_tlv(client_hello_buf, client_hello_length);
            tlv* nn_sig = get_tlv(sh, NONCE);
            tlv* cert_sig = get_tlv(sh, CERTIFICATE);
            tlv* pk_sig = get_tlv(sh, PUBLIC_KEY);
           
            if (ch_sig == NULL) 
                fprintf(stderr, "FRICK ch_sig is NULL!\n");
            if (nn_sig == NULL) 
                fprintf(stderr, "FRICK nn_sig is NULL!\n");

            uint8_t signature_buffer[1024];
            uint16_t signature_buffer_len = 0;
            
            fprintf(stderr, "Got here! Client hello: 0x%x\n", ch_sig->type);

            signature_buffer_len += serialize_tlv(signature_buffer + signature_buffer_len, ch_sig);
            signature_buffer_len += serialize_tlv(signature_buffer + signature_buffer_len, nn_sig);
            signature_buffer_len += serialize_tlv(signature_buffer + signature_buffer_len, cert_sig);
            signature_buffer_len += serialize_tlv(signature_buffer + signature_buffer_len, pk_sig);
           
            fprintf(stderr, "Got here! Post Serialize\n");

            tlv* cert_pub_key = get_tlv(cert_sig, PUBLIC_KEY);
            fprintf(stderr, "Got here! server certificate public key: 0x%x\n", cert_pub_key->type);


            // figure out keys
            load_peer_public_key(cert_pub_key->val, cert_pub_key->length); // public key form servers certificate
            if (verify(sig->val, sig->length, signature_buffer, signature_buffer_len, ec_peer_public_key) == 1) {
                fprintf(stderr, "WERE SO BACK - VERIFIED HANDSHAKE SIGNATURE!\n");
            }
            else 
            {
                fprintf(stderr, "Uh oh - CLIENT FAILED TO VERIFY HANDSHAKE SIGNATURE FRICKED UP\n\n\n");
                exit(3);
            }
        
            // 4. cache the server hello
            memcpy(server_hello_buf, buf, length);
            server_hello_length = length;
            server_hello_recvd = 1;

            // 5. Derive the shared secret
            tlv* server_public_key = get_tlv(sh, PUBLIC_KEY);
            load_peer_public_key(server_public_key->val, server_public_key->length);
            derive_secret();

            // fprintf(stderr, "Public Key %s len: %d \n", server_public_key->val, server_public_key->length);

            uint8_t salt_buf[2048];
            uint16_t salt_buf_len = 0;
            
            tlv* ch_tmp = deserialize_tlv(client_hello_buf, client_hello_length);
            tlv* sh_tmp = deserialize_tlv(server_hello_buf, server_hello_length);

            salt_buf_len += serialize_tlv(salt_buf + salt_buf_len, ch_tmp);
            salt_buf_len += serialize_tlv(salt_buf + salt_buf_len, sh_tmp);

            fprintf(stderr, "DERIVED SHARED KEYS!\n");
            derive_keys(salt_buf, salt_buf_len);
        }
    
        // SERVER: cache client hello
        if (host_type == SERVER && !client_hello_recvd) {
            fprintf(stderr, "CLIENT HELLO RECEIVED\n");

            if (sh->type != CLIENT_HELLO) {
                fprintf(stderr, "Received non-client hello!");
                exit(6);
            } 
            
            // buffer client_hello for signature
            memcpy(client_hello_buf, buf, length);
            client_hello_length = length;

            client_hello_recvd = 1;
        }
        
        // SERVER: verify transcripts
        else if (host_type == SERVER && client_hello_recvd && !client_finished_recvd) {

            // 1. Verifiy client finish transcript
            tlv* ch_tmp = deserialize_tlv(client_hello_buf, client_hello_length);
            tlv* sh_tmp = deserialize_tlv(server_hello_buf, server_hello_length);
    
            uint8_t transcript_buf[2048];
            uint8_t hmac_buf[32];
    
            uint16_t transcript_len = 0;
    
            transcript_len += serialize_tlv(transcript_buf + transcript_len, ch_tmp);
            transcript_len += serialize_tlv(transcript_buf + transcript_len, sh_tmp);
        
            fprintf(stderr, "Transcript Length: %d\n", transcript_len);
            
            hmac(hmac_buf, transcript_buf, transcript_len);
            fprintf(stderr, "hmac calculated: %s\n", hmac_buf);
            fprintf(stderr, "hmac length: %d\n", 32);

            tlv* trans = get_tlv(sh, TRANSCRIPT);

            fprintf(stderr, "Transcript hmac: %s\n", trans->val);
            fprintf(stderr, "Transcript hmac length: %d\n", trans->length);

            // if (strcmp(hmac_buf, (uint8_t *)trans->val) == 0) {
            //     fprintf(stderr, "Transcript verified");
            // }
            // else {
            //     fprintf(stderr, "KMS\n");

            // }
    
            client_finished_recvd = 1;
        }
    
        
        output_io(buf, length);
    }
 

}
