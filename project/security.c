#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Assume this is the file we need to work in

int host_type = -1;
char* host_name = NULL;

void init_sec(int type, char* host) {
    init_io();
    host_type = type;
    host_name = host;
    fprintf(stderr, "Type = %d, Hostname: %s\n", host_type, host_name);


    load_private_key("server_key.bin");
    EVP_PKEY* PRIVATE_KEY = get_private_key();
    set_private_key(PRIVATE_KEY);
    
    derive_public_key(); // GENERATES GLOBAL VARIABLES: #uint8_t* public_key and size_t pub_key_size

    fprintf(stderr, "Generated public key: %d of size %d\n", public_key, pub_key_size);
 
}

// Transport layers call this when making packets!
ssize_t input_sec(uint8_t* buf, size_t max_length) {
    
    int8_t handshake_done = 0;
    if (host_type == CLIENT && !handshake_done) {

        fprintf(stderr, "Client  Creating TLV!\n");

        tlv* ch = create_tlv(CLIENT_HELLO);
        tlv* nn = create_tlv(NONCE);
        uint8_t nonce[NONCE_SIZE];
        generate_nonce(nonce, NONCE_SIZE);

        add_val(nn, nonce, NONCE_SIZE);
        add_tlv(ch, nn);

        // public key
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);
        add_tlv(ch, pk);

        uint16_t len = serialize_tlv(buf, ch);
        free_tlv(ch);
        
        handshake_done = 1;

        return len;
    }
    if (host_type == SERVER && !handshake_done) {
        fprintf(stderr, "Server  Creating TLV!\n");

    }


    return input_io(buf, max_length);
}

// Each time Transport layer receives in-order packet it will call this
void output_sec(uint8_t* buf, size_t length) {
    
    tlv* ch = deserialize_tlv(buf, length);

    if (ch != NULL) {

        tlv* nn = get_tlv(ch, NONCE);
        nn->length; // NONCE_SIZE
        nn->val; // Contains our random nonce


        if (host_type == CLIENT) {

        }
    
        if (host_type == SERVER) {
    
        }
    
        output_io(buf, length);
    }
 

}
