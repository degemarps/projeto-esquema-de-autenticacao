#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <time.h>

int sock, c, new_sock, sock_con, contagem, cont = 0;
struct sockaddr_in client, primario;
char hash[128], hash_resposta[SHA_DIGEST_LENGTH*3];
unsigned char digest[SHA_DIGEST_LENGTH];
char mdhash[SHA_DIGEST_LENGTH*3];
clock_t tempo;

int i,j,k;

unsigned char texto[128];
unsigned char novo[128];

unsigned char auxChave[16];
unsigned char chaves[2][17];
unsigned char chave[17];
unsigned long randomico1;
unsigned long randomico2;
unsigned long chavesSecretas[2];
unsigned char parteHash1[9];
unsigned char parteHash2[11];
char *aux1;
unsigned long parteHashNovo;
unsigned long resul;
unsigned long parteHashNovo2;
unsigned long auxChar_to_Long;
unsigned char senhaDescartavel[11];
unsigned char IDs[2][11];

typedef enum {false,true} bool;

//Pacote voltado para o processo de autenticação de cliente comum
struct Autenticacao {
    unsigned tipo:4;
    char senhaDescartavel[SHA_DIGEST_LENGTH*3];
};

struct Autenticacao autenticacao;

//Pacote contendo o ID do novo cliente e o bit para confirmar ou negar a autenticação dele
struct id{
    unsigned char id[128];
    unsigned autenticado:1;
};

struct id ID;

//Pacote voltado para a criação da chave de criptografia
struct criacaoChave{
    unsigned chaveValida:1;
    unsigned metadeValida:1;
    unsigned long metadeChaveTransporte;
};
struct criacaoChave criacaoChave;

//Função principal
int main (int argc, char *argv[]){

    cont = 0;

    //Criando o socket
    sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock == -1){
        printf("Não foi possível criar o socket!\n");
    }
    puts("Socket criado\n");

    //Prepara a estrutura sockaddr_in
    client.sin_family = AF_INET;
    client.sin_addr.s_addr = INADDR_ANY;
    client.sin_port = htons(1200);

    if (bind(sock, (struct sockaddr *)&client, sizeof(client)) < 0){
        printf("Erro ao criar o bind!\n");
        return 1;
    }

    printf("Bind criado!\n");

    listen(sock, 1);

    //Recebe as mensagens do cliente
    do {

        printf("Esperando uma conexão com o cliente...\n");

        c = sizeof(struct sockaddr_in);

        while ( (new_sock = accept(sock, (struct sockaddr *)&primario, (socklen_t *)&c)) ){
            printf("Conexão estabelecida\n\n");

            recv(new_sock, (void *)&autenticacao, sizeof(autenticacao), 0);

            //Caso seja uma solicitação de autenticação
            if (autenticacao.tipo == 0){

                randomico1 = 0;
                randomico2 = 0;

                srand(time(NULL));

                //Gera um valor randômico
                randomico1 = (unsigned long)1000000000 + rand();

                do {
                    recv(new_sock, (void *)&criacaoChave, sizeof(criacaoChave), 0);

                    //Verificar se o valor recebido para criar a chave é igual ao valor local
                    if (criacaoChave.metadeChaveTransporte == randomico1){
                        criacaoChave.metadeValida = 0;
                        criacaoChave.metadeChaveTransporte = 0;

                        send(new_sock, (void *)&criacaoChave, sizeof(criacaoChave), 0);
                    }else{
                        criacaoChave.metadeValida = 1;
                        randomico2 = criacaoChave.metadeChaveTransporte;
                        criacaoChave.metadeChaveTransporte = randomico1;

                        send(new_sock, (void *)&criacaoChave, sizeof(criacaoChave), 0);

                        break;
                    }

                }while(1);

                printf("Metade da chave gerada localmente: %lu\n", randomico1);
                printf("Metade da chave recebida: %lu\n\n", randomico2);

                //Criação da chave secreta
                //tempo = clock();
                chavesSecretas[cont] = (randomico2&randomico1)^(randomico2|randomico1);

                //tempo = clock() - tempo;

                //printf("Tempo: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

                printf("Chave secreta: %lu\n", chavesSecretas[cont]);

                //Inicialização da chave pública
                snprintf(chaves[cont], sizeof(chaves[cont]), "%lx%lx", chavesSecretas[cont]^randomico2, chavesSecretas[cont]^randomico1);

                printf("Chave de criptografia: %s\n\n", chaves[cont]);

                sprintf(hash, "                                                                                                                                ");

                snprintf(hash, sizeof(hash), "%lx", chavesSecretas[cont]);

                //Processo para criar o hash da chave secreta--------------------------------------
                //tempo = clock();
                SHA1((unsigned char*)&hash, strlen(hash), (unsigned char*)&digest);

                //tempo = clock() - tempo;

                //printf("Tempo: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

                for (i = 0; i<SHA_DIGEST_LENGTH; i++){
                    sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
                }

                printf("Hash da chave secreta: %s\n", mdhash);

                sprintf(chave, "                 ");

                snprintf(chave, sizeof(chave), "%s", chaves[cont]);

                //Processo para criar o hash da chave de criptografia------------------------------
                SHA1((unsigned char*)&chave, strlen(chave), (unsigned char*)&digest);

                for (i = 0; i<SHA_DIGEST_LENGTH; i++){
                    sprintf(&hash_resposta[i*2], "%02x", (unsigned int)digest[i]);
                }

                printf("Hash da chave de criptografia: %s\n\n", hash_resposta);

                contagem = 0;

                //Criação da Chave de Criptografia
                for (i = 0; i<5; i++){

                    aux1 = " ";
                    parteHashNovo = 0;
                    parteHashNovo2 = 0;
                    resul = 0;
                    sprintf(parteHash1, "          ");
                    sprintf(parteHash2, "          ");

                    for (j = 0; j<8; j++){

                        parteHash1[j] = mdhash[j+contagem];
                        parteHash2[j] = hash_resposta[j+contagem];
                    }

                    printf("%dª parte do hash da chave secreta: %s\n", i+1, parteHash1);
                    printf("%d° parte di hash da chave de criptografia: %s\n", i+1, parteHash2);

                    aux1 = parteHash1;

                    parteHashNovo = strtol(aux1, NULL, 16);

                    aux1 = parteHash2;

                    parteHashNovo2 = strtol(aux1, NULL, 16);

                    chavesSecretas[cont] = (parteHashNovo^parteHashNovo2)^chavesSecretas[cont];

                    snprintf(chaves[cont], sizeof(chaves[cont]), "%lx%lx", (chavesSecretas[cont]&parteHashNovo), (chavesSecretas[cont]|parteHashNovo2));

                    aux1 = chaves[cont];

                    auxChar_to_Long = strtol(aux1, NULL, 16);

                    aux1 = chave;

                    resul = strtol(aux1, NULL, 16);

                    snprintf(chaves[cont], sizeof(chaves[cont]), "%lx", resul^auxChar_to_Long);

                    printf("Chave de criptografia para se comunicar com o novo cliente: %s\n\n", chaves[cont]);

                    contagem += 8;
                }

                snprintf(hash, sizeof(hash), "%s", chaves[cont]);

                //Processo para criar o hash da chave de criptografia
                SHA1((unsigned char*)&hash, strlen(hash), (unsigned char*)&digest);

                for (i = 0; i<SHA_DIGEST_LENGTH; i++){
                    sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
                }

                printf("Hash da chave de criptografia para o novo cliente: %s\n", mdhash);

                //Recebe o hash do concentrador
                recv(new_sock, (void *)&hash_resposta, sizeof(hash_resposta), 0);

                //Compara os hashs para validar a chave
                if (strcmp(mdhash, hash_resposta) == 0){
                    printf("Hashs iguais! Chave de criptografia definida!\n\n");

                    criacaoChave.chaveValida = 1;
                    criacaoChave.metadeValida = 0;
                    criacaoChave.metadeChaveTransporte = 0;

                    send(new_sock, (void *)&criacaoChave, sizeof(criacaoChave), 0);

                    //Inicia o processo para autenticar o cliente
                    //Primeiro será definida a senha descartável do cliente
                    sprintf(texto, "                                                                                                                                ");
                    recv(new_sock, (void *)&texto, sizeof(texto), 0);

                    unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];

                    sprintf(iv_enc, "          ");

                    sprintf(iv_dec, "          ");

                    printf("IV_ENC = %s\n", iv_enc);

                    printf("IV_DEC = %s\n", iv_dec);

                    AES_KEY enc_key, dec_key;

                    //tempo = clock();
                    AES_set_decrypt_key(chaves[cont], 128, &dec_key);
                    AES_cbc_encrypt(texto, novo, sizeof(texto), &dec_key, iv_dec, AES_DECRYPT);

                    //tempo = tempo - clock();

                    //printf("TEMPO: %lf\n", ((double)tempo/(CLOCKS_PER_SEC/1000)));

                    printf("--------------------- = %s\n", novo);

                    aux1 = novo;

                    randomico1 = strtol(aux1, NULL, 16);

                    randomico2 = (unsigned long)1000000000 + rand();

                    sprintf(texto, "                                                                                                                                ");

                    snprintf(texto, sizeof(texto), "%lu", randomico2);

                    sprintf(novo, "                                                                                                                                ");

                    AES_set_encrypt_key(chaves[cont], 128, &enc_key);
                    AES_cbc_encrypt((unsigned char *)&texto, novo, sizeof(texto), &enc_key, iv_enc, AES_ENCRYPT);


                    send(new_sock, (void *)&novo, sizeof(novo), 0);

                    printf("CHAVE SECRETA: %lu\n", chavesSecretas[cont]);
                    printf("RANDÔMICO 2: %lu\n", randomico2);

                    sprintf(senhaDescartavel, "           ");

                    snprintf(senhaDescartavel, sizeof(senhaDescartavel), "%lx", chavesSecretas[cont]^randomico2);

                    printf("SENHA DESCARTÁVEL: %s\n", senhaDescartavel);

                    //Processo para criar o hash da chave secreta
                    SHA1((unsigned char*)&senhaDescartavel, sizeof(senhaDescartavel), (unsigned char*)&digest);

                    for (i = 0; i<SHA_DIGEST_LENGTH; i++){
                        sprintf(&mdhash[i*2], "%02x", (unsigned int)digest[i]);
                    }

                    printf("Hash da senha descartável: %s\n", mdhash);

                    contagem = 0;

                    //Criação da senha descartável
                    for (i = 0; i<5; i++){

                        aux1 = " ";
                        parteHashNovo = 0;
                        parteHashNovo2 = 0;
                        sprintf(parteHash1, "          ");

                        for (j = 0; j<8; j++){

                            parteHash1[j] = mdhash[j+contagem];
                        }

                        printf("\n%d° Parte do hash: %s\n", i+1, parteHash1);

                        aux1 = parteHash1;

                        parteHashNovo = strtol(aux1, NULL, 16);

                        aux1 = senhaDescartavel;

                        parteHashNovo2 = strtol(aux1, NULL, 16);

                        snprintf(senhaDescartavel, sizeof(senhaDescartavel), "%lx", (chavesSecretas[cont]^parteHashNovo)^parteHashNovo2);

                        aux1 = senhaDescartavel;

                        parteHashNovo2 = strtol(aux1, NULL, 16);

                        chavesSecretas[cont] = (randomico2^chavesSecretas[cont])^parteHashNovo2;

                        contagem += 10;
                    }

                    sprintf(digest, "                    ");

                    //Processo para criar o hash da senha descartável
                    SHA1((unsigned char*)&senhaDescartavel, sizeof(senhaDescartavel), (unsigned char*)&digest);

                    for (i = 0; i<SHA_DIGEST_LENGTH; i++){
                        sprintf(&hash_resposta[i*2], "%02x", (unsigned int)digest[i]);
                    }

                    printf("Hash da  Senha Descartável: %s\n", hash_resposta);

                    sprintf(texto, "                                                                                                                                ");

                    //Recebe a senha descartável criptografada
                    recv(new_sock, (void *)&texto, sizeof(texto), 0);

                    sprintf(novo, "                                                                                                                                ");

                    AES_set_decrypt_key(chaves[cont], 128, &dec_key);
                    AES_cbc_encrypt(texto, novo, sizeof(texto), &dec_key, iv_dec, AES_DECRYPT);

                    //Verifica se as senhas descartáveis são iguais
                    //Caso sejam iguais, será definido um identificador para o novo cliente
                    if (strcmp(hash_resposta, novo) == 0){

                        printf("Senhas descartáveis iguais!\n\n");

                        sprintf(senhaDescartavel, "           ");

                        ID.autenticado = 1;

                        resul = randomico1^chavesSecretas[cont];

                        snprintf(IDs[cont], sizeof(IDs[cont]), "%lx", resul);
                        snprintf(texto, sizeof(texto), "%lx", resul);

                        sprintf(novo, "                                                                                                                                ");

                        AES_set_encrypt_key(chaves[cont], 128, &enc_key);
                        AES_cbc_encrypt((unsigned char *)&texto, novo, sizeof(texto), &enc_key, iv_enc, AES_ENCRYPT);

                        sprintf(ID.id, "%s", novo);

                        send(new_sock, (void *)&ID, sizeof(ID), 0);

                    }else{

                        printf("Senhas descartáveis diferentes!\n");

                        ID.autenticado = 0;

                        send(new_sock, (void *)&ID, sizeof(ID), 0);
                    }

                }else{
                    printf("Hashs diferentes! Chave de criptografia não definida!\n");

                    criacaoChave.metadeValida = 0;
                    criacaoChave.chaveValida = 0;
                    criacaoChave.metadeChaveTransporte = 0;

                    send(new_sock, (void *)&criacaoChave, sizeof(criacaoChave), 0);
                }

                printf("Chave Pública: %s\nID: %s\n\n", chaves[0], IDs[0]);
            }

            close(new_sock);
            break;
    }

    }while(1);

    return 0;
}
