# Projet de recherche sur les générateurs pseudo-aléatoires + Programmation en C d'un CTR DRBG basé sur AES

**Objectifs de ce projet universitaire (Master 1) :**
- Apprendre à travailler à plusieurs : travail en binôme
- Faire un travail de recherche
- Apprendre à partir de documentations officielles à créer une implémentation (peu importe le langage) en rapport avec le sujet choisi
- Créer un rapport solide en LaTex comprenant une partie implémentation, rédigé en anglais
- Oral de fin d'année sur ce projet, en s'exprimant en anglais pendant une partie de l'oral

**Programmation :**
1 - main.c : programme principal
Il récupère d'abord 48 octets d'aléa réel depuis : /dev/urandom. Ces données servent à initialiser le générateur CTR-DRBG. Ensuite, le programme demande au CTR-DRBG de générer des octets : ctr_drbg_generate(&ctx, output, length, NULL); Par défaut, il génère 64 octets (./aes). On peut choisir la quantité : ./aes 16 <-- 16 octets, ./aes 64 <-- 64 octets,./aes 128 <-- 128 octets.

2 - ctr_drbg.c : coeur du générateur
Il contient la logique du CTR-DRBG : il utilise une clé et un état interne pour produire des données pseudo-aléatoires. Il peut également faire un reseed lorsqu'il atteint une limite de génération.

3 - Les fichiers AES 
Tous les fichiers suivants implémentent les différentes étapes de AES-256 :
- aes.c
- sub_bytes.c
- shift_rows.c
- mix_columns.c
- add_round_key.c
- key_expansion.c
- tables.c
Le CTR-DRBG s'appuie donc sur une implémentation d'AES pour générer les données.

**Commandes pour le terminal :**
cd ~/Documents/CTR-DRBG/aes_ctr_drbg_project  
make *compilation des fichiers .c*  
./aes *lancement du générateur*  
./test/run_tests *lancement des tests*  



