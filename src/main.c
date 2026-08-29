#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h> // Pour open()
#include <unistd.h> // Pour read() et close()
#include "ctr_drbg.h"

void get_randomness(uint8_t *buffer, size_t length) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("Erreur : impossible d'ouvrir /dev/urandom");
        exit(EXIT_FAILURE);
    }
    
    ssize_t result = read(fd, buffer, length);
    if (result < 0 || (size_t)result != length) {
        perror("Erreur lors de la lecture de l'entropie");
        close(fd);
        exit(EXIT_FAILURE);
    }
    close(fd);
}

int main(int argc, char **argv) {
    
    // Définir une longueur par défaut (ex: 64)
    size_t length = 64; 

    // Si l'utilisateur passe un argument, on l'utilise comme longueur
    if (argc > 1) {
        int input_length = atoi(argv[1]);
        if (input_length > 0) {
            length = (size_t)input_length;
        } else {
            printf("Erreur : la longueur doit être un entier positif.\n");
            return 1;
        }
    }

    CTR_DRBG_CTX ctx;
    
    // il faut 48 octets d'entropie pure pour AES-256
    uint8_t entropy[48];

    // Allouer dynamiquement le tableau en fonction de la taille demandée
    uint8_t *output = (uint8_t *)malloc(length * sizeof(uint8_t));
    if (output == NULL) {
        printf("Erreur d'allocation mémoire.\n");
        return 1;
    }

    // Remplir le tableau avec du hasard physique (48 octets)
    get_randomness(entropy, sizeof(entropy));

    // Initialisation (pas de nonce, on passe NULL pour la personalization string)
    ctr_drbg_init(&ctx, entropy, NULL);
    
    // Générer le nombre d'octets demandés (on passe NULL pour l'additional_input)
    int status = ctr_drbg_generate(&ctx, output, length, NULL);

    // Si le générateur est bloqué 
    if (status != 0) {
        printf("Le générateur a atteint sa limite. Réamorçage en cours...\n");

        // 1. On va chercher de la nouvelle entropie physique (48 octets obligatoires)
        uint8_t new_entropy[48];
        get_randomness(new_entropy, sizeof(new_entropy));

        // 2. On débloque le générateur avec la fonction reseed (NULL pour l'additional_input)
        ctr_drbg_reseed(&ctx, new_entropy, NULL);

        // 3. On relance la génération qui avait échoué
        ctr_drbg_generate(&ctx, output, length, NULL);
    }

    // Afficher le résultat
    for (size_t i = 0; i < length; i++) {
        // On ajoute un espace après le %02x
        printf("%02x ", output[i]); 

        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    
    // Retour à la ligne final si la taille n'est pas un multiple de 16
    if (length % 16 != 0) {
        printf("\n");
    }

    // Effacement sécurisé du contexte DRBG de la mémoire
    ctr_drbg_uninstantiate(&ctx);

    // Libérer la mémoire allouée
    free(output);

    return 0;
}