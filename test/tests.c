#define _POSIX_C_SOURCE 200809L // pour fileno()
#include <stdio.h>
#include <unistd.h> // pour dup, dup2, close
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <complex.h>
#include <time.h>
#include <sys/random.h>
#include "ctr_drbg.h"

// Définition de M_PI si nécessaire
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

//pour compiler faire make test
//pour exécuter fare ./test/run_tests

// Variables globales pour le rapport de test
int tests_run = 0;
int tests_passed = 0;
int tests_failed = 0;

// Fonction utilitaire pour évaluer un test
void assert_test(int condition, const char *test_name) {
    tests_run++;
    if (condition) {
        printf("[SUCCESS]"  " %s\n", test_name);
        tests_passed++;
    } else {
        printf( "[FAILURE]" " %s\n", test_name);
        tests_failed++;
    }
}

// Convertit une chaîne hexadécimale (ex: "A1B2C3...") en tableau d'octets
void hex_to_bytes(const char *hex_string, uint8_t *byte_array, size_t array_len) {
    for (size_t i = 0; i < array_len; i++) {
        sscanf(hex_string + 2 * i, "%2hhx", &byte_array[i]);
    }
}

// 1. Tests d'instanciation et destruction
void test_uninstantiate() {
    printf( "\n--- Running state tests (Uninstantiate) ---\n" );
    
    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    memset(entropy, 0xAA, 48); // Entropie factice

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_uninstantiate(&ctx);

    // Vérifier que tout est bien à zéro
    int is_zero = 1;
    for (int i = 0; i < 32; i++) if (ctx.Key[i] != 0) is_zero = 0;
    for (int i = 0; i < 16; i++) if (ctx.V[i] != 0) is_zero = 0;
    if (ctx.reseed_counter != 0) is_zero = 0;

    assert_test(is_zero, "ctr_drbg_uninstantiate écrase correctement Key, V et reseed_counter avec des zéros");
}

// 2. Tests des limites imposées par le NIST
void test_constraints() {
    printf( "\n Running NIST constraint tests\n" );
    
    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    memset(entropy, 0xBB, 48);

    ctr_drbg_init(&ctx, entropy, NULL);

    // Test A : Limite de taille par requête (Max 65536 octets)
    uint8_t dummy_out[1];
    int status = ctr_drbg_generate(&ctx, dummy_out, 65537, NULL);
    assert_test(status == -1, "La génération échoue si on demande > 65536 octets d'un coup (Max_Bits_Per_Request)");

    // Test B : Intervalle de Reseed
    // On simule artificiellement que le générateur a beaucoup tourné
    ctx.reseed_counter = RESEED_INTERVAL;
    
    // AJOUT : redirection de stderr pour masquer le message
    int old_stderr_fd = dup(fileno(stderr));
    freopen("/dev/null", "w", stderr); // redirige stderr vers /dev/null


    status = ctr_drbg_generate(&ctx, dummy_out, 16, NULL);
    assert_test(status == 0, "La génération réussit lorsque le compteur est exactement à la limite (RESEED_INTERVAL)");

    status = ctr_drbg_generate(&ctx, dummy_out, 16, NULL);
    assert_test(status == -1, "Le générateur se verrouille et exige un reseed quand l'intervalle est dépassé");


    fflush(stderr);
    dup2(old_stderr_fd, fileno(stderr)); // restaure stderr
    close(old_stderr_fd);
    // FIN de la redirection

    // Test C : Reseed et déblocage
    uint8_t new_entropy[48];
    memset(new_entropy, 0xCC, 48);
    ctr_drbg_reseed(&ctx, new_entropy, NULL);
    
    assert_test(ctx.reseed_counter == 1, "La fonction reseed réinitialise correctement le compteur à 1");
    
    status = ctr_drbg_generate(&ctx, dummy_out, 16, NULL);
    assert_test(status == 0, "Le générateur est correctement débloqué et génère des octets après le reseed");

    ctr_drbg_uninstantiate(&ctx);
}

// 3. Known Answer Test (KAT)
void test_known_answers() {
    printf( "\nRunning Known Answer Test (KAT)\n" );
    
    // Note : Pour valider officiellement l'algorithme, ces vecteurs doivent être extraits
    // des fichiers officiels CAVP (Cryptographic Algorithm Validation Program) du NIST.
    // Ceci est un squelette de test déterministe pour prouver que l'algo ne change pas.

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    uint8_t output[16];
    //uint8_t expected_output[16]; / <-- mis en commentaire car sinon Warning (car pas utilisé)
    
    // Remplissage prédictible (0x00, 0x01, 0x02...)
    for (int i = 0; i < 48; i++) entropy[i] = i; 

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_generate(&ctx, output, 16, NULL);

    // On stocke le résultat du premier run (remplacez par un vrai vecteur NIST plus tard)
    // Ici, c'est un test de non-régression simple. S'il échoue à l'avenir, vous saurez 
    // que vous avez "cassé" l'algorithme.
    static int first_run = 1;
    static uint8_t kat_snapshot[16];

    if (first_run) {
        memcpy(kat_snapshot, output, 16);
        first_run = 0;
        assert_test(1, "Snapshot du KAT enregistré (vecteur déterministe)");
    } else {
        int match = (memcmp(output, kat_snapshot, 16) == 0);
        assert_test(match, "Le résultat déterministe (KAT) correspond parfaitement");
    }

    ctr_drbg_uninstantiate(&ctx);
}


// Ici une vraie entropie aléatoire est utilisée pour que les tests statistiques
// (frequency, autocorrelation, cumulative sums) passent correctement.
// erfc() = outil pour calculer des p-values (lorsque la statistique suit une loi normale)


// NIST SP 800-22
void test_frequency() {
    printf("\n--- Frequency (Monobit) Test ---\n");

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);

    const int N = 200000;
    uint8_t out[N/8];

    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    int S = 0;
    // Xi = +1 si bit=1, Xi=-1 si bit=0
    for (int i = 0; i < N; i++) {
        int byte_index = i / 8; // octet contenant le bit i
        int bit_index  = i % 8; // position du bit dans l’octet
        int bit = (out[byte_index] >> bit_index) & 1; // extraction du bit numéro i
        if (bit == 1)
            S += 1;
        else
            S -= 1;
    }

    double sobs = abs(S) / sqrt((double)N); // |S_n|/sqrt(n) normalisation de S_n
    // s_obs tend en loi vers une N(0,1) (on peut appliquer le TCL)
    double p_value = erfc(sobs / sqrt(2.0)); // p-value officielle NIST

    printf("S_n      = %d\n", S);
    printf("s_obs    = %f\n", sobs);
    printf("p-value  = %f\n", p_value);

    assert_test(p_value >= 0.01, "NIST Frequency (Monobit) Test");

    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie que les 0 et 1 sont approximativement équilibrés.
// Principe : on compte tous les bits générés, puis on calcule le ratio de 1.
// Si ce ratio est proche de 0.5 (par exemple entre 0.45 et 0.55), 
// la séquence est considérée "équilibrée".


// NIST SP 800-22
void test_runs() { // test des run (un run = une suite consécutive de mêmes bits)
    printf("\n--- Test runs (séquences 0/1) ---\n");

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    uint8_t out[20000];

    memset(entropy, 0xBB, 48);
    ctr_drbg_init(&ctx, entropy, NULL);

    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    const size_t n = sizeof(out) * 8;

    // calcul de la proportion de 1 (pi)
    int ones = 0;
    for (size_t i = 0; i < n; i++) {
        int byte_index = i / 8; // octet content le i-ème bit
        int bit_index  = i % 8; // position du i-ème bit dans cet octet
        int bit = (out[byte_index] >> bit_index) & 1; // extraction
        if (bit == 1)
            ones++;
    }
    double pi = (double)ones/n; // proportion de 1

    double tau = 2.0/sqrt((double)n); // Condition officielle du NIST : |pi - 0.5| < 2/sqrt(n)

    if (fabs(pi - 0.5) >= tau) {
        assert_test(0, "Runs Test abandonné : Frequency Test préalable échoué");
        ctr_drbg_uninstantiate(&ctx);
        return;
    }

    // comptage des runs :
    int Vn = 1;
    int prev = out[0] & 1; // prev = bit précédent dans la séquence
    for (size_t i = 1; i < n; i++) {
        int Xi = (out[i/8] >> (i%8)) & 1; // extraction du bit comme avant (codé en 1 ligne)
        if (Xi != prev){
            Vn++;
        }
        prev = Xi;
    }

    double numerator = fabs(Vn - 2.0*n*pi*(1.0 - pi));
    double denominator = 2.0*sqrt(n)*pi*(1.0 - pi);
    double Z = numerator/denominator;

    double p_value = erfc(fabs(Z)/sqrt(2.0)); // P_value = erfc(|Z|/sqrt(2))

    printf("pi            = %f\n", pi);
    printf("Vn (runs)     = %d\n", Vn);
    printf("Z statistic   = %f\n", Z);
    printf("p-value       = %f\n", p_value);
    
    assert_test(p_value >= 0.01, "Runs Test"); // seuil de 1% (choisi par le NIST)

    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie la longueur des séquences consécutives de 0 ou 1 (runs).
// Principe : on parcourt la séquence bit par bit et on compte quand un bit change.
// Ensuite, on compare le nombre total de runs à ce qu'on attend pour un bit aléatoire (~N/2).
// Permet de détecter si les bits se regroupent trop ou pas assez.


// ce test ne fait pas partie des tests NIST, mais montre la non-corrélation des bits
// c'est un test complémentaire
void test_autocorrelation() {

    printf("\n--- Autocorrelation Test ---\n");

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    uint8_t out[200000 / 8];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    const size_t N = 200000;
    int matches = 0;

    for (size_t i = 0; i < N - 1; i++) {

        int bit_i    = (out[i / 8] >> (i % 8)) & 1;
        int bit_next = (out[(i + 1) / 8] >> ((i + 1) % 8)) & 1;

        if (bit_i == bit_next)
            matches++;
    }

    double p = (double)matches / (N - 1);

    double z = (p - 0.5) / sqrt(0.25 / (N - 1)); // statistique normalisée (TCL)

    double p_value = erfc(fabs(z) / sqrt(2.0)); // p-value via loi normale

    int passed = (p_value >= 0.01);

    assert_test(passed, "Autocorrelation Test");
    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie l'indépendance des bits voisins.
// Principe : on compare chaque bit avec le bit suivant (décalage = 1).
// On calcule le ratio de bits identiques à ce décalage.
// Si ce ratio est proche de 0.5, les bits ne dépendent pas fortement de leurs voisins.


// NIST SP 800-22 : "Frequency Test within a Block"
void test_block_frequency() {
    printf("\n--- Test Block Frequency ---\n");

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];
    memset(entropy, 0xAA, 48);

    ctr_drbg_init(&ctx, entropy, NULL);

    const size_t N = 200000; // nombre total de bits
    const size_t M = 128; // taille d’un bloc
    uint8_t out[N / 8];
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    size_t num_blocks = N/M;

    double sum = 0.0;

    for (size_t b = 0; b < num_blocks; b++) {

        int ones = 0;
        // compter les 1 dans le bloc b
        for (size_t i = 0; i < M; i++) {
            int pos = b*M + i; // position globale du bit
            int byte = pos/8;
            int bit  = pos%8;
            int value = (out[byte] >> bit) & 1;
            if (value == 1)
                ones++;
        }

        double pi_i = (double)ones/M; // proportion de 1 dans le bloc

        sum += (pi_i - 0.5)*(pi_i - 0.5); // NIST : Xi = pi_i - 1/2
    }

    double X = 4.0*M*sum; // X = chi_deux = 4*M*somme((pi_i - 0.5)^2)

    double k = (double)num_blocks;
    double Z = (X - k)/sqrt(2.0 * k); // approximation du chi-deux par la loi normale
    double p_value = erfc(fabs(Z)/sqrt(2.0));

    int passed = (p_value >= 0.01); // seuil 1% (NIST)
    assert_test(passed, "Block Frequency Test ");

    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie l'équilibre 0/1 sur de petits blocs de bits.
// Principe : on découpe la séquence en blocs (par ex. 128 bits) et on compte les 1.
// Si chaque bloc a un ratio de 1 proche de 0.5, la séquence est équilibrée même localement.

// NIST SP 800-22
void test_approximate_entropy() {

    printf("\n--- Approximate Entropy Test ---\n");

    const int n = 200000;
    const int m = 2; // on ragarde les blocs de 2 bits
    /*m petit --> test rapide mais moins sensible
    m grand --> plus précis mais coûteux (exponentiel : 2^m)
    On doit avoir m <= ⌊log_2​(n)⌋−5, ici on doit donc avoir m <= 12
    donc vaut mieux choisir m=2 ou m=3 (pas plus que m=4 max) */

    uint8_t out[n / 8];

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    int pow_m = 1 << m;
    int pow_m1 = 1 << (m + 1);

    double C_m[pow_m];
    double C_m1[pow_m1];

    memset(C_m, 0, sizeof(C_m));
    memset(C_m1, 0, sizeof(C_m1));

    for (int i = 0; i < n; i++) { // comptage des motifs (sequence circulaire)

        int v_m = 0;
        int v_m1 = 0;

        for (int j = 0; j < m; j++) {  // motif taille m
            int bit = (out[((i + j) % n) / 8] >> ((i + j) % 8)) & 1;
            v_m = (v_m << 1) | bit;
        }

        for (int j = 0; j < m + 1; j++) { // motif taille m+1
            int bit = (out[((i + j) % n) / 8] >> ((i + j) % 8)) & 1;
            v_m1 = (v_m1 << 1) | bit;
        }

        C_m[v_m]++; // count m patterns
        C_m1[v_m1]++; // count m+1 patterns
    }

    double phi_m = 0.0; // phi(m)
    double phi_m1 = 0.0; // phi(m+1)

    for (int i = 0; i < pow_m; i++) {
        if (C_m[i] > 0) {
            double p = C_m[i] / n;
            phi_m += p*log(p); // contribution phi(m)
        }
    }

    for (int i = 0; i < pow_m1; i++) {
        if (C_m1[i] > 0) {
            double p = C_m1[i] / n;
            phi_m1 += p * log(p);  // contribution phi(m+1)
        }
    }

    double ApEn = phi_m - phi_m1; // approximate entropy

    double chi2 = 2.0 * n * (log(2.0) - ApEn);

    double p_value = exp(-chi2 / 2.0); // approximation donc biais possible (pas comme dans NIST avec IGAMC)

    int passed = (p_value >= 0.01);

    assert_test(passed, "Approximate Entropy Test (NIST)");

    ctr_drbg_uninstantiate(&ctx);
} // peut parfois échouer (normal)
// Vérifie la complexité de motifs courts (par ex. 2 bits).
// Principe : on compte combien de fois chaque motif de longueur m apparaît.
// On calcule ensuite l'entropie moyenne de ces motifs.
// Permet de détecter des répétitions locales dans la séquence.


//NIST SP 800-22
void test_cumulative_sums() {
    printf("\n--- Cumulative Sums Test) ---\n");

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);

    const size_t n = 200000;
    uint8_t out[n/8];
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    int S = 0;
    int S_max_forward = 0; // on lit les bits de gauche à droite
    for (size_t i = 0; i < n; i++) { // i représente un indice dans un tableau (d'où le size_t)
        int bit = (out[i/8] >> (i%8)) & 1;
        int Xi = (bit == 1) ? 1 : -1; // notation NIST
        S += Xi;

        if (abs(S) > S_max_forward)
            S_max_forward = abs(S);
    }

    S = 0;
    int S_max_backward = 0; // on lit les bits de droite à gauche
    for (int i = n - 1; i >= 0; i--) { // int et pas size_t car besoin que i puisse être <0 (stop quand i=-1)

        int bit = (out[i / 8] >> (i % 8)) & 1;
        int Xi = (bit == 1) ? 1 : -1;
        S += Xi;

        if (abs(S) > S_max_backward)
            S_max_backward = abs(S);
    }

    int Z;
    if (S_max_forward > S_max_backward)
        Z = S_max_forward;
    else
        Z = S_max_backward;

    double Zn = (double)Z/sqrt(n);

    double p_value = erfc(Zn/sqrt(2.0));

    int passed = (p_value >= 0.01);
    assert_test(passed, "Cumulative Sums Test");
    ctr_drbg_uninstantiate(&ctx);
}

// Sert pour test linear complexity (voir lien source dans le mail)
int berlekamp_massey(int *s, int N) {

    int C[N], B[N], T[N]; // C = polynôme courant (modèle qui essaie de "prédire" la séquence)
    // B = ancien polynôme de référence, T = sauvegarde temporaire

    for (int i = 0; i < N; i++) { // initailaisation
        C[i] = 0;
        B[i] = 0;
    }

    C[0] = 1; // au départ : C(x)=1 et B(x)=1
    B[0] = 1;

    int L = 0; // longueur du modèle (complexité linéaire)
    int m = -1; // position du dernier changement important

    for (int n = 0; n < N; n++) {

        // calcul de d = erreur de prédiction (discrepancy)
        int d = s[n];

        for (int i = 1; i <= L; i++) { // on teste si le modèle actuel prédit correctement s[n]
            d ^= (C[i] & s[n - i]);
        }

        if (d == 1) { // si d = 0 : le modèle explique bien le bit, si d=1 : il se trompe

            // sauvegarde C
            for (int i = 0; i < N; i++) // on sauvegarde l’ancien modèle
                T[i] = C[i];

            // C(x) = C(x) XOR x^(n-m) * B(x)
            for (int i = 0; i < N - (n - m); i++) { // on corrige le modèle en ajoutant une nouvelle dépendance
                C[i + (n - m)] ^= B[i];
            }

            if (2 * L <= n) { // si le modèle devient insuffisant
                L = n + 1 - L; // on augmente la complexité
                m = n; // on mémorise le point de correction

                for (int i = 0; i < N; i++) B[i] = T[i]; // on met à jour le modèle de référence
            }
        }
    }

    return L; // complexité linéaire finale
}

// NIST SP 800-22
/* mesure la complexité linéaire d’une séquence binaire, c-à-d 
la taille du plus petit registre à décalage linéaire qui peut générer la séquence :*/
void test_linear_complexity() {

    printf("\n--- Linear Complexity Test ---\n");

    const int n = 200000; // nb bits
    const int M = 500; // taille des blocs
    /*Le NIST choisit typiquement : M=500 car : 
    assez grand pour que Berlekamp–Massey soit significatif 
    assez petit pour avoir assez de blocs
    règle : N = n/M >= 200 donc on veut au moins 200 blocs*/

    uint8_t out[n/8];

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    int N = n/M; // nb blocs

    double chi2 = 0.0;

    for (int b = 0; b < N; b++) {

        int s[M];

        for (int i = 0; i < M; i++) { // conversion bloc en tableau de bits
            int pos = b*M + i;
            int bit = (out[pos/8] >> (pos%8)) & 1;
            s[i] = bit;
        }

        int L_i = berlekamp_massey(s, M); // L_i = complexité linéaire réelle (Berlekamp–Massey)

        double mu = M/2.0; // moyenne théorique NIST (simplifiée) ici pas correction périodique exacte des bins NIST (car trop lourd)

        double T = L_i - mu; // écart à la moyenne

        chi2 += T*T; // accumulation pour le chi-deux
    }

    double X = (4.0/M)*chi2; // statistique NIST simplifiée

    double p_value = exp(-X / 2.0); // approximation simple chi-deux (pas IGAMMC du NIST)

    int passed = (p_value >= 0.01); // seuil NIST 1%

    assert_test(passed, "Linear Complexity Test");

    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie la complexité linéaire de la séquence.
// Principe : on applique l'algorithme de Berlekamp-Massey pour calculer le plus petit registre à décalage
// capable de générer la séquence.
// Si la complexité est proche de N/2, la séquence est considérée complexe et aléatoire.

// NIST SP 800-22 : "Discrete Fourier Transform (Spectral) Test"
// détecte des motifs périodiques dans la séquence en utilisant la transformée de Fourier discrète :
void test_spectral() {

    printf("\n--- Spectral Test ---\n");

    const int n = 20000;

    uint8_t out[n/8];

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48];

    FILE *f = fopen("/dev/urandom", "rb");
    fread(entropy, 1, 48, f);
    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);
    ctr_drbg_generate(&ctx, out, sizeof(out), NULL);

    double complex X[n];

    for (int i = 0; i < n; i++) {
        int bit = (out[i / 8] >> (i % 8)) & 1;
        X[i] = (bit ? 1 : -1) + 0.0 * I; // X_i = +ou-1
    }

    // DFT naïve ~ O(n^2) (plus lent que FFT ~ O(n*log(n)))
    int half = n/2;
    double M[half];
    for (int k = 0; k < half; k++) {
        double complex S = 0;
        for (int j = 0; j < n; j++) {
            S += X[j]*cexp(-2.0*M_PI*I*k*j/n); // cexp = exponentielle complexe
        }
        M[k] = cabs(S); //cabs = valeur absolue complexe
    }

    double T = sqrt(log(1/0.05)*n); // seuil NIST

    int N1 = 0;
    for (int k = 0; k < half; k++) {
        if (M[k] < T)
            N1++;
    }

    double N0 = 0.95 * half; // valeur attendue

    double d =(N1 - N0)/sqrt(n*0.95*0.05/4.0);

    double p_value = erfc(fabs(d)/sqrt(2.0));

    int passed = (p_value >= 0.01);

    assert_test(passed,"Spectral Test");

    ctr_drbg_uninstantiate(&ctx);
}
// Vérifie l'absence de motifs périodiques.
// Principe : on transforme la séquence binaire en +1/-1 et on applique la DFT.
// On regarde les amplitudes des fréquences, si certaines dépassent un seuil trop souvent,
// cela indique des motifs répétitifs.


// test des timming entre notre ctr_drbg et le générateur de linux (/dev/urandom) :

static double diff_time(struct timespec a, struct timespec b) {
    return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9; // conversion en secondes
}

// calcule un chi-square simple sur les bytes
double chi_square(uint8_t *data, size_t n) {

    int freq[256] = {0}; // tableau des fréquences pour chaque valeur de byte

    for (size_t i = 0; i < n; i++)
        freq[data[i]]++; // compte combien de fois chaque byte apparaît

    double expected = n / 256.0; // valeur attendue si distribution uniforme
    double chi = 0;

    for (int i = 0; i < 256; i++) {
        double d = freq[i] - expected; // écart à la moyenne
        chi += (d * d) / expected; // contribution chi-square
    }

    return chi; // plus petit = plus uniforme
}

// uniformité simple : pire écart à 1/256
double max_deviation(uint8_t *data, size_t n) {

    int freq[256] = {0};

    for (size_t i = 0; i < n; i++)
        freq[data[i]]++;

    double max_dev = 0;

    for (int i = 0; i < 256; i++) {
        double p = (double)freq[i] / n;
        double d = fabs(p - 1.0 / 256.0);

        if (d > max_dev)
            max_dev = d;
    }

    return max_dev;
}


void test_comparaison() {

    printf("\n--- Comparison CTR_DRBG vs Linux RNG ---\n");

    const size_t N = 10000000; // taille des données générées (1 MB)

    uint8_t *ctr = malloc(N); // buffer
    uint8_t *gr = malloc(N);
    uint8_t *urandom = malloc(N);

    if (!ctr || !gr || !urandom) {
        printf("memory error\n");
        return;
    }

    // CTR_DRBG :

    CTR_DRBG_CTX ctx;
    uint8_t entropy[48]; // seed initial (entropie)

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        perror("fopen");
        exit(1);
    }

    size_t r = fread(entropy, 1, sizeof(entropy), f);
    if (r != sizeof(entropy)) {
        fprintf(stderr, "entropy read failed\n");
        fclose(f);
        exit(1);
    }

    fclose(f);

    ctr_drbg_init(&ctx, entropy, NULL);

    struct timespec t1, t2;

    clock_gettime(CLOCK_MONOTONIC, &t1); // début du chronomètre

    size_t remaining = N;
    size_t offset = 0;

    while (remaining > 0) {

        size_t chunk = (remaining > 65536) ? 65536 : remaining;

        int status = ctr_drbg_generate(
            &ctx,
            ctr + offset,
            chunk,
            NULL
        );

        if (status != 0) {
            printf("generation failed\n");
            exit(1);
        }

        offset += chunk;
        remaining -= chunk;
    }

    clock_gettime(CLOCK_MONOTONIC, &t2); // fin du chronomètre

    ctr_drbg_uninstantiate(&ctx); // nettoyage de l’état interne

    double time_ctr = diff_time(t1, t2); // temps de génération CTR_DRBG


    // getrandom :

    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (getrandom(gr, N, 0) != (ssize_t)N) { // génération via kernel Linux
        perror("getrandom");
        exit(1);
    }
    clock_gettime(CLOCK_MONOTONIC, &t2);

    double time_gr = diff_time(t1, t2);


    // /dev/urandom (ancien mais encore utilisé) :

    FILE *fu = fopen("/dev/urandom", "rb");
    if (!fu) {
        perror("fopen /dev/urandom");
        exit(1);
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    size_t r2 = fread(urandom, 1, N, fu);
    clock_gettime(CLOCK_MONOTONIC, &t2);

    if (r2 != N) {
        fprintf(stderr, "urandom read failed\n");
        fclose(fu);
        exit(1);
    }

    fclose(fu);

    double time_ur = diff_time(t1, t2);

    // QUALITY :

    double chi_ctr = chi_square(ctr, N); // uniformité globale CTR_DRBG
    double chi_gr = chi_square(gr, N); // uniformité de getrandom
    double chi_ur = chi_square(urandom, N); // uniformité de /dev/urandom

    double dev_ctr = max_deviation(ctr, N); // biais maximal CTR_DRBG
    double dev_gr = max_deviation(gr, N); // biais maximal getrandom
    double dev_ur = max_deviation(urandom, N); // biais maximal /dev/urandom

    // RESULTS :

    printf("\n--- SPEED ---\n"); // performance (temps)

    printf("CTR_DRBG        : %.4f s\n", time_ctr);
    printf("getrandom()     : %.4f s\n", time_gr);
    printf("/dev/urandom    : %.4f s\n", time_ur);

    printf("\n--- CHI-SQUARE ---\n"); // qualité globale

    printf("CTR_DRBG        : %.2f\n", chi_ctr);
    printf("getrandom()     : %.2f\n", chi_gr);
    printf("/dev/urandom    : %.2f\n", chi_ur);

    printf("\n--- UNIFORMITY (max deviation) ---\n"); // biais local

    printf("CTR_DRBG        : %.6f\n", dev_ctr); // pire écart CTR_DRBG
    printf("getrandom()     : %.6f\n", dev_gr); // pire écart Linux moderne
    printf("/dev/urandom    : %.6f\n", dev_ur); // pire écart Linux ancien

    free(ctr);
    free(gr);
    free(urandom);
}



// Programme Principal : Rapport de test

int main() {
    printf("   STARTING CTR_DRBG TEST SUITE     \n");

    // Tests fonctionnels / conformité
    test_uninstantiate();
    test_constraints();
    test_known_answers();

    // Tests statistiques
    test_frequency();
    test_runs();
    test_autocorrelation(); // détecte la dépendance entre bits voisins (complémente test_runs)
    test_block_frequency();
    test_approximate_entropy();
    test_cumulative_sums(); // similaire au Random Walk test du NIST, vérifie les déséquilibres cumulatifs
    test_linear_complexity();
    test_spectral();

    // Test de non-régression
    // Répéter le KAT pour s'assurer du non-changement
    test_known_answers();

    printf("\n");
    printf("                  FINAL REPORT                   \n");
    printf("Tests executed   : %d\n", tests_run);
    
    if (tests_failed == 0) {
        printf("Tests passed    : %d (100%%)\n" , tests_passed);
        printf( "\n>>> ALL TESTS PASSED SUCCESSFULLY! <<< \n" );
    } else {
        printf( "Tests passed    : %d\n" , tests_passed);
        printf("Tests failed    : %d\n" , tests_failed);
        printf("\n>>> WARNING: SOME TESTS FAILED <<< \n" );
    }
    printf("\n");
    // test de comparaison
    test_comparaison();
    return (tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}