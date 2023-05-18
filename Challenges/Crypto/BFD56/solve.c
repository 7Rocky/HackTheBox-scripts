// gcc solve.c -O3 -o bifid -lm

#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "qgr.h"


#define ALPHABET "ABCDEFGHIKLMNOPQRSTUVWXYZ"
#define COUNT 10000
#define PERIOD 8
#define STEP 0.1
#define TEMP 20


extern float qgram[];


double score_text_qgram(char* text, int length) {
        int i;
        char temp[4];
        double score = 0;

        for (i = 0; i < length - 3; i++) {
                temp[0] = text[i + 0] - 'A';
                temp[1] = text[i + 1] - 'A';
                temp[2] = text[i + 2] - 'A';
                temp[3] = text[i + 3] - 'A';

                score += qgram[17576 * temp[0] + 676 * temp[1] + 26 * temp[2] + temp[3]];
        }

        return score;
}

void strunmask(char* message, char* mask) {
        int i;
        int a, b;

        for (i = 0; i < PERIOD; i++) {
                a = (int) (index(ALPHABET, message[i]) - ALPHABET);
                b = (int) (index(ALPHABET, mask[i]) - ALPHABET);

                message[i] = ALPHABET[(25 + a - b) % 25];
        }
}

void decrypt_block(char* key, char* ct_block, char* pt_block) {
        int i;
        int a_ind, b_ind;
        int a_row, b_row;
        int a_col, b_col;
        char a, b;

        for (i = 0; i < PERIOD; i++) {
                a = ct_block[i / 2];
                b = ct_block[(PERIOD + i) / 2];

                a_ind = (int) (index(key, a) - key);
                b_ind = (int) (index(key, b) - key);

                a_row = a_ind / 5;
                b_row = b_ind / 5;
                a_col = a_ind % 5;
                b_col = b_ind % 5;

                if (i % 2 == 0) {
                        pt_block[i] = key[5 * a_row + b_row];
                } else {
                        pt_block[i] = key[5 * a_col + b_col];
                }
        }
}

void bifid_decrypt(char* key, char* iv, char* ct, char* pt) {
        while (*ct) {
                decrypt_block(key, ct, pt);
                strunmask(pt, iv);

                iv = ct;
                ct += PERIOD;
                pt += PERIOD;
        }
}

void exchange_letters(char* key) {
        int i = rand() % 25;
        int j = rand() % 25;
        char temp = key[i];
        key[i] = key[j];
        key[j] = temp;
}

float bifid_crack(char* best_key, char* iv, char* ct, int length) {
        int i, j, count;
        float t;
        char temp;
        char* pt = malloc(length + 1);
        char test_key[26];
        char max_key[26];
        double prob, diff, max_score, score;
        double best_score;

        strcpy(max_key, best_key);
        bifid_decrypt(max_key, iv, ct, pt);
        max_score = score_text_qgram(pt, length);
        best_score = max_score;

        for (t = TEMP; t >= 0; t -= STEP) {
                for (count = 0; count < COUNT; count++) {
                        strcpy(test_key, max_key);
                        exchange_letters(test_key);
                        bifid_decrypt(test_key, iv, ct, pt);
                        score = score_text_qgram(pt, length);
                        diff = score - max_score;

                        if (diff >= 0) {
                                max_score = score;
                                strcpy(max_key, test_key);
                        } else if (t > 0) {
                                prob = exp(diff / t);

                                if (prob > 1.0 * rand() / RAND_MAX) {
                                        max_score = score;
                                        strcpy(max_key, test_key);
                                }
                        }

                        if (max_score > best_score) {
                                best_score = max_score;
                                strcpy(best_key, max_key);
                        }
                }
        }

        free(pt);

        return best_score;
}

int main(int argc, char** argv) {
        char* iv;
        char* ciphertext;

        if (argc != 3) {
                printf("[-] Usage: %s <iv> <ciphertext>\n", argv[0]);
                return 1;
        }

        iv = argv[1];
        ciphertext = argv[2];

        int length = strlen(ciphertext);
        char* plaintext = malloc(length + 1);
        char key[] = "ABCDEFGHIKLMNOPQRSTUVWXYZ";

        bifid_crack(key, iv, ciphertext, length);
        bifid_decrypt(key, iv, ciphertext, plaintext);

        printf("[*] Key: %s\n[+] Plaintext: %s\n", key, plaintext);

        free(plaintext);

        return 0;
}
