#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 9090
#define BUFFER_SIZE 2048

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    char command[BUFFER_SIZE];

    // Создание сокета
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Преобразование адреса
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        return -1;
    }

    // Подключение к серверу
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return -1;
    }

    // Чтение приветственного сообщения
    int bytes_read = read(sock, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) {
        printf("Failed to read from server. Exiting...\n");
        close(sock);
        return -1;
    }
    printf("%s", buffer);

    while (1) {
        // Ввод команды
        printf("Enter command: ");
        if (fgets(command, BUFFER_SIZE, stdin) == NULL) {
            printf("Input error. Exiting...\n");
            break;
        }

        // Убираем символ новой строки
        command[strcspn(command, "\n")] = 0;

        // Проверка на пустой ввод
        if (strlen(command) == 0) {
            continue;
        }

        // Отправка команды
        if (send(sock, command, strlen(command), 0) <= 0) {
            printf("Failed to send command to server. Exiting...\n");
            break;
        }

        // Очистка буфера перед чтением ответа
        memset(buffer, 0, BUFFER_SIZE);

        // Чтение ответа сервера
        bytes_read = read(sock, buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            printf("Server disconnected. Exiting...\n");
            break;
        }

        printf("Server response:\n%s", buffer);

        // Отправляем подтверждение получения, если это часть истории сессий
        if (strncmp(command, "session_history", 15) == 0) {
            while (strstr(buffer, "End of session history.") == NULL) {
                send(sock, "ACK", 4, 0);
                bytes_read = read(sock, buffer, BUFFER_SIZE);
                if (bytes_read <= 0) {
                    printf("Server disconnected during session history. Exiting...\n");
                    break;
                }
                printf("%s", buffer);
            }
        }

        // Обработка игры
        if (strncmp(command, "game", 4) == 0 && strstr(buffer, "Authentication required") == NULL) {
            if (strstr(buffer, "Game started") != NULL) {
                while (1) {
                    // Ввод для игры
                    memset(command, 0, BUFFER_SIZE);
                    printf("Enter game input: ");
                    if (fgets(command, BUFFER_SIZE, stdin) == NULL) {
                        printf("Input error. Exiting game...\n");
                        break;
                    }

                    // Убираем символ новой строки
                    command[strcspn(command, "\n")] = 0;

                    if (strlen(command) == 0) {
                        continue;
                    }

                    // Отправка данных игры
                    if (send(sock, command, strlen(command), 0) <= 0) {
                        printf("Failed to send game input to server. Exiting game...\n");
                        break;
                    }

                    // Очистка буфера перед чтением ответа
                    memset(buffer, 0, BUFFER_SIZE);

                    // Чтение ответа сервера
                    bytes_read = read(sock, buffer, BUFFER_SIZE);
                    if (bytes_read <= 0) {
                        printf("Server disconnected during game. Exiting...\n");
                        close(sock);
                        return -1;
                    }

                    printf("Server response:\n%s", buffer);

                    // Проверка условия завершения игры
                    if (strstr(buffer, "Correct!") || strstr(buffer, "Game over!") || strstr(buffer, "Game ended")) {
                        // После завершения игры очищаем буфер и выходим из цикла игры
                        memset(buffer, 0, BUFFER_SIZE);
                        break;
                    }
                }
            }
        }

        // Проверка команды выхода
        if (strncmp(command, "exit", 4) == 0) {
            break;
        }
    }

    close(sock);
    return 0;
}