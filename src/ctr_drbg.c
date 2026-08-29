#include "ctr_drbg.h"

// Incrémentation du compteur V (big-endian)
static void increment_V(uint8_t V[16]) {
    for (int i = 15; i >= 0; i--) {
        V[i]++;
        if (V[i] != 0) {
            break;
        }
    }
}

// mise à jour de la clé et du vecteur V en utilisant la clé actuelle
static void ctr_drbg_update(CTR_DRBG_CTX *ctx, const uint8_t *provided_data) {
    uint8_t temp[48]; // 32 octets (Key) + 16 octets (V) pour AES-256
    uint8_t block[16];
    AESRoundKeys rk;
    
    // On étend la clé ACTUELLE pour chiffrer
    KeyExpansion(ctx->Key, rk);

    // Générer 48 octets en chiffrant les compteurs successifs
    for (int i = 0; i < 3; i++) {
        increment_V(ctx->V);                     // V = V + 1
        AES_encrypt_block(ctx->V, block, rk);    // Chiffrer V
        memcpy(temp + (i * 16), block, 16);      // Stocker le bloc dans temp
    }

    //  XOR avec les provided_data
    if (provided_data != NULL) {
        for (int i = 0; i < 48; i++) {
            temp[i] ^= provided_data[i];
        }
    }

    // Mettre à jour le contexte avec les nouvelles valeurs
    memcpy(ctx->Key, temp, 32);       // Les 32 premiers octets = Nouvelle Clé
    memcpy(ctx->V, temp + 32, 16);    // Les 16 suivants = Nouveau Vecteur V

    //  Nettoyage de sécurité (effacer les traces en mémoire)
    memset(temp, 0, sizeof(temp));
    memset(block, 0, sizeof(block));
    memset(rk, 0, sizeof(rk));
}

// Initialisation
void ctr_drbg_init(CTR_DRBG_CTX *ctx, const uint8_t *entropy, const uint8_t *perso_string) {
    //on met tout à zéro
    memset(ctx->Key, 0, 32);
    memset(ctx->V, 0, 16);
    ctx->reseed_counter = 1;

    uint8_t seed_material[48];
    memcpy(seed_material, entropy, 48); // Entropy MUST be 48 bytes

    // XOR personalization string into seed_material if provided
    if (perso_string != NULL) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= perso_string[i];
        }
    }
    //on utilise update pour utilis l'entropie
    ctr_drbg_update(ctx, seed_material);
    memset(seed_material, 0, sizeof(seed_material));
}

// Génération
int ctr_drbg_generate(CTR_DRBG_CTX *ctx,uint8_t *output,size_t outlen, const uint8_t *additional_input
) { //on vérifie les conditions
    if (outlen > 65536) { // NIST Max limit (2^19 bits)
        return -1; 
    }

    if (ctx->reseed_counter > RESEED_INTERVAL) {
        fprintf(stderr, "Erreur : Reseed requis !\n");
        return -1;
    }

    if (additional_input != NULL) {
        ctr_drbg_update(ctx, additional_input);
    }

    AESRoundKeys rk;
    KeyExpansion(ctx->Key, rk);

    size_t produced = 0;
    //boucle de génération : on incrémente V, on chiffre, on copie dans output
    while (produced < outlen) {
        increment_V(ctx->V);
        uint8_t block[16];
        AES_encrypt_block(ctx->V, block, rk);

        size_t n = (outlen - produced > 16) ? 16 : (outlen - produced);
        memcpy(output + produced, block, n);
        produced += n;
        memset(block, 0, sizeof(block));
    }

    ctr_drbg_update(ctx, additional_input); // Update again to prevent backtracking
    ctx->reseed_counter++;

    memset(rk, 0, sizeof(rk));
    return 0;
}

// Mise à jour de l'état avec une nouvelle entropie (reseed)
void ctr_drbg_reseed(CTR_DRBG_CTX *ctx, const uint8_t *new_entropy, const uint8_t *additional_input) {
    uint8_t seed_material[48];
    memcpy(seed_material, new_entropy, 48); 
    
    if (additional_input != NULL) {
        for (int i = 0; i < 48; i++) {
            seed_material[i] ^= additional_input[i];
        }
    }

    ctr_drbg_update(ctx, seed_material);
    ctx->reseed_counter = 1;
    memset(seed_material, 0, sizeof(seed_material));
}

//libère la mémoire proprement
void ctr_drbg_uninstantiate(CTR_DRBG_CTX *ctx) {
    memset(ctx->Key, 0, 32);
    memset(ctx->V, 0, 16);
    ctx->reseed_counter = 0;
}