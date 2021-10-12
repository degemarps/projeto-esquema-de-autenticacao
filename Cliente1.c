#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>

typedef enum {false,true} bool;

int sock, c, new_sock, sock_admin, sock_secundario, contagem;
struct sockaddr_in server;
char hash[128], hash_resposta[SHA_DIGEST_LENGTH*3];
unsigned char digest[SHA_DIGEST_LENGTH];
char mdhash[SHA_DIGEST_LENGTH*3];
clock_t tempo;

int i,j,k;

unsigned char texto[128];
unsigned char novo[128];

unsigned char auxChave[16];
unsigned char chaveAdmin[17];
unsigned char chaveSecundario[17];
unsigned char chavesClients[2][17];
unsigned char chave[17];
unsigned char parteHash1[11];
unsigned char parteHash2[11];
unsigned long randomico1;
char *aux1;
unsigned long randomico2;
unsigned long chavesSecretas[3];
unsigned long chaveSecretaSecundario;
unsigned long parteHashNovo;
unsigned long parteHashNovo2;
unsigned long resul;
unsigned long auxChar_to_Long;
unsigned char senhaDescartavel[11];
unsigned char identificador[11];

//Pacote voltado para o processo de autenticação de cliente comum
struct Autenticacao{
    unsigned tipo:4;
    char senhaDescartavel[SHA_DIGEST_LENGTH*3];
};
struct Autenticacao autenticacao;

//Pacote contendo o ID
struct id {
    unsigned char id[128];
    unsigned autenticacao:1;
};
struct id ID;

//Pacote voltado para a criação da chave de criptografia
struct criacaoChave{
    unsigned chaveValida:1;
    unsigned metadeValida:1;
    unsigned long metadeChaveTransporte;
};
struct criacaoChave criacaoChave;

unsigned long chaveSecretaeCriptografia (unsigned long metadeChave1, unsigned long metadeChave2, unsigned long chaveSecreta, unsigned char *chaveCriptografia, size_t chaveCriptografiaSize){

    //Criação da chave secreta
    //tempo = clock();
    chaveSecreta = (metadeChave2&metadeChave1)^(metadeChave2|metadeChave1);
    //tempo = clock() - tempo;

    //printf("Tempo: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

    printf("Chave secreta: %lu\n", chaveSecreta);

    //Inicialização da chave pública
    snprintf(chaveCriptografia, chaveCriptografiaSize, "%lx%lx", chaveSecreta^metadeChave1, chaveSecreta^metadeChave2);

    printf("Chave de criptografia: %s\n\n", chaveCriptografia);

    //Processo para criar o hash da chave secreta----------------------------------
    snprintf(hash, sizeof(hash), "%lx", chaveSecreta);

    //tempo = clock();
    SHA1((unsigned char*)&hash, strlen(hash), (unsigned char*)&digest);

    //tempo = clock() - tempo;

    //printf("Tempo: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

    for (i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
    }

    printf("Hash da chave secreta: %s\n", mdhash);

    //Processo para criar o hash da chave de criptografia--------------------------
    snprintf(chave, sizeof(chave), "%s", chaveCriptografia);

    SHA1((unsigned char*)&chave, strlen(chave), (unsigned char*)&digest);

    for (i = 0; i < SHA_DIGEST_LENGTH; i++){
        sprintf(&hash_resposta[i*2], "%02x", (unsigned int)digest[i]);
    }

    printf("Hash da chave de criptografia: %s\n\n", hash_resposta);

    contagem = 0;

    //Criação da Chave de Criptigrafia
    for (i = 0; i<5; i++){

        aux1 = " ";
        parteHashNovo = 0;
        parteHashNovo2 = 0;
        resul = 0;

        for (j = 0; j<8; j++){

            parteHash1[j] = mdhash[j+contagem];
            parteHash2[j] = hash_resposta[j+contagem];
        }

        printf("%dª parte do hash da chave secreta: %s\n", i+1, parteHash1);
        printf("%d° parte do hash da chave de criptografia: %s\n", i+1, parteHash2);

        aux1 = parteHash1;

        parteHashNovo = strtol(aux1, NULL, 16);

        aux1 = parteHash2;

        parteHashNovo2 = strtol(aux1, NULL, 16);

        chaveSecreta = (parteHashNovo^parteHashNovo2)^chaveSecreta;

        snprintf(chaveCriptografia, chaveCriptografiaSize, "%lx%lx", (chaveSecreta&parteHashNovo), (chaveSecreta|parteHashNovo2));

        aux1 = chaveCriptografia;

        auxChar_to_Long = strtol(aux1, NULL, 16);

        aux1 = chave;

        resul = strtol(aux1, NULL, 16);

        snprintf(chaveCriptografia, chaveCriptografiaSize, "%lx", resul^auxChar_to_Long);

        printf("Chave de criptografia para se comunicar com o servidor: %s\n\n", chaveCriptografia);

        contagem += 8;

    }

    return chaveSecreta;
}

//Função para se conectar com o servidor
struct Autenticacao conect_admin (struct Autenticacao autenticacao){

    struct sockaddr_in admin;
    sock_admin = socket(AF_INET, SOCK_STREAM, 0);

    if (sock_admin == -1){
        printf("Socket do servidor não criado!\n\n");
    }
    printf("Socket do servidor criado!\n\n");

    admin.sin_family = AF_INET;
    admin.sin_addr.s_addr = inet_addr("192.168.0.1");
    admin.sin_port = htons(1200);

    //Se conectando com o servidor
    if (connect(sock_admin, (struct sockaddr *)&admin, sizeof(admin)) < 0){
        printf("Conexão com o servidor não estabelecida!\n");
    }else{

        //Para se autenticar no servidor
        if (autenticacao.tipo == 0){

            srand(time(NULL));

            send(sock_admin, (void *)&autenticacao, sizeof(autenticacao), 0);

            do{

                randomico1 = 0;
                criacaoChave.metadeChaveTransporte = 0;

                //Antes será definida a chave de criptografia
                //Gera um valor randômico
                randomico1 = (unsigned long)1000000000 + rand();

                criacaoChave.metadeChaveTransporte = randomico1;

                send(sock_admin, (void *)&criacaoChave, sizeof(criacaoChave), 0);

                recv(sock_admin, (void *)&criacaoChave, sizeof(criacaoChave), 0);

                if (criacaoChave.metadeValida == 1){
                    break;
                }

            }while(1);

            printf("Metade da chave gerada localmente: %lu\n", randomico1);
            printf("Metade da chave recebida: %lu\n\n", criacaoChave.metadeChaveTransporte);

            //Chama a função para gerar a chave secreta e a chave de criptografia
            chavesSecretas[0] = chaveSecretaeCriptografia(randomico1, criacaoChave.metadeChaveTransporte, chavesSecretas[0], chaveAdmin, sizeof(chaveAdmin)/sizeof(*chaveAdmin));

            printf("Chave secreta do Administrador: %lu\n", chavesSecretas[0]);
            printf("Chave de criptografia do Administrador: %s\n", chaveAdmin);

            sprintf(hash, "                                                                                                                                ");

            snprintf(hash, sizeof(hash), "%s", chaveAdmin);

            //Processo para criar o hash da chave de criptografia
            SHA1((unsigned char*)&hash, strlen(hash), (unsigned char*)&digest);

            for (i = 0; i < SHA_DIGEST_LENGTH; i++){
                sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
            }

            printf("Hash da chave de criptografia do servidor: %s\n", mdhash);

            //Envia o hash para o servidor
            send(sock_admin, (void *)&mdhash, sizeof(mdhash), 0);

            recv(sock_admin, (void *)&criacaoChave, sizeof(criacaoChave), 0);

            //Verifica se a chave de criptografia é válida
            if (criacaoChave.chaveValida == 1){
                printf("Chave de criptografia definida com sucesso!\n\n");

                //Início do processo de autenticação no servidor
                //Primeiro será definida a senha descartável do servidor
                randomico1 = (unsigned long)1000000000 + rand();

                snprintf(texto, sizeof(texto), "%lx", randomico1);

                unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];

                sprintf(iv_enc, "          ");

                sprintf(iv_dec, "          ");

                printf("IV_ENC = %s\n", iv_enc);

                printf("IV_DEC = %s\n", iv_dec);

                AES_KEY enc_key, dec_key;

                //tempo = clock();
                AES_set_encrypt_key(chaveAdmin, 128, &enc_key);
                AES_cbc_encrypt((unsigned char *)&texto, novo, sizeof(texto), &enc_key, iv_enc, AES_ENCRYPT);

                //tempo = tempo - clock();

                //printf("TEMPO: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

                sprintf(ID.id, "%s", novo);

                send(sock_admin, (void *)&ID.id, sizeof(ID.id), 0);

                sprintf(texto, "                                                                                                                                ");

                recv(sock_admin, (void *)&texto, sizeof(texto), 0);

                sprintf(novo, "                                                                                                                                ");

                //tempo = clock();
                AES_set_decrypt_key(chaveAdmin, 128, &dec_key);
                AES_cbc_encrypt(texto, novo, sizeof(texto), &dec_key, iv_dec, AES_DECRYPT);

                //tempo = tempo - clock();

                //printf("TEMPO: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

                aux1 = novo;

                randomico2 = strtol(aux1, NULL, 10);

                printf("CHAVE SECRETA: %lu\n", chavesSecretas[0]);
                printf("RANDÔMICO 2: %lu\n", randomico2);

                sprintf(senhaDescartavel, "           ");

                snprintf(senhaDescartavel, sizeof(senhaDescartavel), "%lx", chavesSecretas[0]^randomico2);

                printf("SENHA DESCARTÁVEL: %s\n", senhaDescartavel);

                sprintf(digest, "                    ");

                //Processo para criar o hash da chave secreta
                SHA1((unsigned char*)&senhaDescartavel, sizeof(senhaDescartavel), (unsigned char*)&digest);

                for (i = 0; i < SHA_DIGEST_LENGTH; i++){
                    sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
                }

                printf("Hash da senha descartável: %s\n", mdhash);

                contagem = 0;

                //Criação da senha descartável
                for (i = 0; i<5; i++){

                    aux1 = " ";
                    parteHashNovo = 0;
                    parteHashNovo2 = 0;

                    for (j = 0; j<8; j++){

                        parteHash1[j] = mdhash[j+contagem];
                    }

                    printf("\n%d° Parte do hash: %s\n", i+1, parteHash1);

                    aux1 = parteHash1;

                    parteHashNovo = strtol(aux1, NULL, 16);

                    aux1 = senhaDescartavel;

                    parteHashNovo2 = strtol(aux1, NULL, 16);

                    snprintf(senhaDescartavel, sizeof(senhaDescartavel), "%lx", (chavesSecretas[0]^parteHashNovo)^parteHashNovo2);

                    aux1 = senhaDescartavel;

                    parteHashNovo2 = strtol(aux1, NULL, 16);

                    chavesSecretas[0] = (randomico2^chavesSecretas[0])^parteHashNovo2;

                    contagem += 10;
                }

                //Processo para criar o hash do valor gerado
                SHA1((unsigned char*)&senhaDescartavel, sizeof(senhaDescartavel), (unsigned char*)&digest);

                for (i = 0; i < SHA_DIGEST_LENGTH; i++){
                    sprintf(&hash_resposta[i*2], "%02x", (unsigned int)digest[i]);
                }

                printf("Hash da senha descartável: %s\n", hash_resposta);

                sprintf(novo, "                                                                                                                                ");

                AES_set_encrypt_key(chaveAdmin, 128, &enc_key);
                AES_cbc_encrypt((unsigned char *)&hash_resposta, novo, sizeof(hash_resposta), &enc_key, iv_enc, AES_ENCRYPT);

                //Envia a senha descartável criptografada
                send(sock_admin, (void *)&novo, sizeof(novo), 0);

                recv(sock_admin, (void *)&ID, sizeof(ID), 0);

                printf("O que recebi: %d\n", ID.autenticacao);

                //Caso a senha descartável seja válida, será iniciado o processo de criação do identificador
                if (ID.autenticacao == 1){

                    printf("Autenticação realizada com sucesso!\n\n");

                    sprintf(senhaDescartavel, "           ");

                    sprintf(novo, "                                                                                                                                ");

                    AES_set_decrypt_key(chaveAdmin, 128, &dec_key);
                    AES_cbc_encrypt(ID.id, novo, sizeof(ID.id), &dec_key, iv_dec, AES_DECRYPT);

                    sprintf(identificador, "%s", novo);

                    printf("CHAVE PUBLICA: %s\n", chaveAdmin);
                    printf("ID: %s\n\n", identificador);

                }else{

                    printf("Falha na autenticação!\n");
                }

            }else{
                printf("Chave de criptografia não definida!\n");
            }

        }

        close(sock_admin);
    }
}

int main (int argc, char *argv[]){

    autenticacao.tipo = 0;
	conect_admin(autenticacao);

	return 0;
}
