#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/utsname.h>

#define PORT 9090
#define BUFFER_SIZE 2048
#define KEY_SIZE 32
#define IV_SIZE 16
#define MAX_ATTEMPTS 3
#define LOCKOUT_TIME 60 // Время блокировки в секундах

int server_fd;
unsigned char key[KEY_SIZE];
unsigned char iv[IV_SIZE];
pthread_mutex_t client_lock = PTHREAD_MUTEX_INITIALIZER;
int active_clients = 0;
pthread_mutex_t client_count_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int client_socket;
    int authenticated;
    int in_game;
    int failed_attempts; // Число неудачных попыток
    time_t lock_until;   // Время до которого клиент заблокирован
    char username[BUFFER_SIZE];
} Client;

void *idle_shutdown(void *arg) {
    while (1) {
        sleep(60); // Проверка каждые 60 секунд

        pthread_mutex_lock(&client_count_lock);
        if (active_clients == 0) {
            printf("No active users for 60 seconds. Shutting down server...\n");
            close(server_fd);
            exit(0);
        }
        pthread_mutex_unlock(&client_count_lock);
    }
    return NULL;
}

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void generate_key_and_iv(unsigned char *key, unsigned char *iv) {
    if (!RAND_bytes(key, KEY_SIZE) || !RAND_bytes(iv, IV_SIZE)) {
        handle_errors("Key/IV generation failed");
    }
}

void handle_exit_signal(int sig) {
    printf("\nShutting down server...\n");
    close(server_fd);
    exit(0);
}

void hash_password(const char *password, unsigned char *hashed_password) {
    SHA256((unsigned char *)password, strlen(password), hashed_password);
}

void handle_myinfo(Client *client) {
    if (!client->authenticated) {
        send(client->client_socket, "Authentication required to view client info.\n", 45, 0);
        return;
    }

    char client_info[BUFFER_SIZE];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client->client_socket, (struct sockaddr *)&addr, &addr_len);

    // Получаем IP и порт клиента
    snprintf(client_info, BUFFER_SIZE, "Client IP: %s, Port: %d\n",
             inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

    // Используем uname для получения системной информации
    struct utsname sys_info;
    if (uname(&sys_info) == 0) {
        snprintf(client_info + strlen(client_info), BUFFER_SIZE - strlen(client_info),
                 "System Name: %s\nNode Name: %s\nRelease: %s\nVersion: %s\nMachine: %s\n",
                 sys_info.sysname,  // Название операционной системы
                 sys_info.nodename, // Имя узла (hostname)
                 sys_info.release,  // Версия ядра
                 sys_info.version,  // Полная версия ОС
                 sys_info.machine); // Архитектура процессора
    } else {
        snprintf(client_info + strlen(client_info), BUFFER_SIZE - strlen(client_info),
                 "System information: Unable to retrieve.\n");
    }

    // Добавляем текущее системное время
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    snprintf(client_info + strlen(client_info), BUFFER_SIZE - strlen(client_info),
             "Current Time: %s\n", time_str);

    // Отправляем информацию клиенту
    send(client->client_socket, client_info, strlen(client_info), 0);
}

void register_user(Client *client, const char *username, const char *password) {
    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    pthread_mutex_lock(&client_lock);
    FILE *file = fopen("users.txt", "r");
    if (file) {
        char line[BUFFER_SIZE];
        while (fgets(line, sizeof(line), file)) {
            char file_username[BUFFER_SIZE];
            if (sscanf(line, "%[^:]:", file_username) == 1) {
                if (strcmp(username, file_username) == 0) {
                    send(client->client_socket, "Username already exists. Choose a different username.\n", 53, 0);
                    fclose(file);
                    pthread_mutex_unlock(&client_lock);
                    return;
                }
            }
        }
        fclose(file);
    }

    file = fopen("users.txt", "a");
    if (!file) {
        perror("Error opening users file for registration");
        send(client->client_socket, "Registration failed.\n", 21, 0);
        pthread_mutex_unlock(&client_lock);
        return;
    }

    fprintf(file, "%s:", username);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        fprintf(file, "%02x", hashed_password[i]);
    }
    fprintf(file, "\n");
    fclose(file);

    pthread_mutex_unlock(&client_lock);
    send(client->client_socket, "Registration successful.\n", 25, 0);
}

void authenticate_user(Client *client, const char *username, const char *password) {
    time_t now = time(NULL);
    if (client->failed_attempts >= MAX_ATTEMPTS && now < client->lock_until) {
        send(client->client_socket, "Account temporarily locked. Try again later.\n", 45, 0);
        return;
    }

    unsigned char hashed_password[SHA256_DIGEST_LENGTH];
    hash_password(password, hashed_password);

    pthread_mutex_lock(&client_lock);
    FILE *file = fopen("users.txt", "r");
    if (!file) {
        perror("Error opening users file");
        send(client->client_socket, "Authentication failed.\n", 22, 0);
        pthread_mutex_unlock(&client_lock);
        return;
    }

    char line[BUFFER_SIZE];
    int authenticated = 0;
    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE], file_password[SHA256_DIGEST_LENGTH * 2 + 1];
        if (sscanf(line, "%[^:]:%s", file_username, file_password) == 2) {
            if (strcmp(username, file_username) == 0) {
                char hashed_password_str[SHA256_DIGEST_LENGTH * 2 + 1] = {0};
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    snprintf(&hashed_password_str[i * 2], 3, "%02x", hashed_password[i]);
                }
                if (strcmp(file_password, hashed_password_str) == 0) {
                    authenticated = 1;
                    break;
                }
            }
        }
    }
    fclose(file);
    pthread_mutex_unlock(&client_lock);

    if (authenticated) {
        client->authenticated = 1;
        strncpy(client->username, username, sizeof(client->username) - 1);
        client->username[sizeof(client->username) - 1] = '\0';
        send(client->client_socket, "Authentication successful.\n", 28, 0);
        client->failed_attempts = 0;
    } else {
        send(client->client_socket, "Authentication failed.\n", 22, 0);
        client->failed_attempts++;
        if (client->failed_attempts >= MAX_ATTEMPTS) {
            client->lock_until = time(NULL) + LOCKOUT_TIME;
        }
    }
}

void log_session(const char *username, const char *command) {
    FILE *file = fopen("sessions.txt", "a");
    if (!file) {
        perror("Error opening sessions file");
        return;
    }

    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Логирование в файл
    fprintf(file, "[%s] User: %s Command: %s\n", time_str, username ? username : "Unknown", command);
    fclose(file);

    // Логирование в консоль
    printf("[%s] User: %s used: %s\n", time_str, username ? username : "Unknown", command);
}


void handle_session_history(Client *client) {
    if (!client->authenticated) {
        send(client->client_socket, "Authentication required to view session history.\n", 51, 0);
        return;
    }

    FILE *file = fopen("sessions.txt", "r");
    if (!file) {
        perror("Error opening session history file");
        send(client->client_socket, "Unable to retrieve session history.\n", 36, 0);
        return;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), file)) {
        char file_username[BUFFER_SIZE], command[BUFFER_SIZE];
        char time_str[64];

        if (sscanf(line, "[%63[^]]] User: %s Command: %[^\n]", time_str, file_username, command) == 3) {
            if (strcmp(client->username, file_username) == 0) {
                // Ограничиваем длину команды, чтобы избежать переполнения
                char formatted_command[BUFFER_SIZE / 2];
                snprintf(formatted_command, sizeof(formatted_command), "%.500s", command);

                // Проверяем доступное место перед форматированием строки
                size_t max_possible_length = strlen(time_str) + strlen(formatted_command) + 20; // 20 - фиксированный текст
                if (max_possible_length < BUFFER_SIZE) {
                    snprintf(line, BUFFER_SIZE, "[%s] Command: %s\n", time_str, formatted_command);
                    send(client->client_socket, line, strlen(line), 0);

                    // Ожидание подтверждения от клиента
                    char ack[BUFFER_SIZE] = {0};
                    read(client->client_socket, ack, sizeof(ack));
                } else {
                    fprintf(stderr, "Formatted line too long, skipping entry.\n");
                }
            }
        }
    }
    fclose(file);

    send(client->client_socket, "End of session history.\n", 25, 0);
}

void handle_game(Client *client) {
    if (!client->authenticated) {
        send(client->client_socket, "Authentication required to play the game. Please log in using 'auth <username> <password>'.\n", 95, 0);
        return;
    }

    if (client->in_game) {
        send(client->client_socket, "You are already in a game. Please finish the current game first.\n", 66, 0);
        return;
    }

    client->in_game = 1;
    char buffer[BUFFER_SIZE] = {0};
    char response[BUFFER_SIZE] = {0};
    int lower, upper, secret, max_attempts, attempts = 0;
    int game_over = 0;

    snprintf(response, BUFFER_SIZE, "Enter range (lower-upper): ");
    send(client->client_socket, response, strlen(response), 0);

    memset(buffer, 0, BUFFER_SIZE);
    int bytes_read = read(client->client_socket, buffer, BUFFER_SIZE);
    if (bytes_read <= 0) {
        snprintf(response, BUFFER_SIZE, "Failed to receive range input. Game terminated.\nGame ended. Enter next command.\n");
        send(client->client_socket, response, strlen(response), 0);
        client->in_game = 0;
        return;
    }
    buffer[strcspn(buffer, "\n")] = 0;

    if (sscanf(buffer, "%d-%d", &lower, &upper) != 2 || lower >= upper) {
        snprintf(response, BUFFER_SIZE, "Invalid range. Game terminated.\nGame ended. Enter next command.\n");
        send(client->client_socket, response, strlen(response), 0);
        client->in_game = 0;
        return;
    }

    srand(time(NULL) ^ client->client_socket);
    secret = lower + rand() % (upper - lower + 1);
    max_attempts = (int)ceil(log2(upper - lower + 1));
    snprintf(response, BUFFER_SIZE, "Game started! Guess between %d and %d. You have %d attempts.\n", lower, upper, max_attempts);
    send(client->client_socket, response, strlen(response), 0);

    while (attempts < max_attempts && !game_over) {
        memset(buffer, 0, BUFFER_SIZE);
        bytes_read = read(client->client_socket, buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            snprintf(response, BUFFER_SIZE, "Failed to receive guess input. Game terminated.\nGame ended. Enter next command.\n");
            send(client->client_socket, response, strlen(response), 0);
            client->in_game = 0;
            return;
        }
        buffer[strcspn(buffer, "\n")] = 0;

        int guess;
        if (sscanf(buffer, "%d", &guess) != 1 || guess < lower || guess > upper) {
            snprintf(response, BUFFER_SIZE, "Invalid input. Must be a number between %d and %d.\n", lower, upper);
            send(client->client_socket, response, strlen(response), 0);
            continue;
        }

        attempts++;
        if (guess > secret) {
            snprintf(response, BUFFER_SIZE, "Too high! Attempts left: %d.\n", max_attempts - attempts);
        } else if (guess < secret) {
            snprintf(response, BUFFER_SIZE, "Too low! Attempts left: %d.\n", max_attempts - attempts);
        } else {
            snprintf(response, BUFFER_SIZE, "Correct! You guessed the number in %d attempts.\nGame ended. Enter next command.\n", attempts);
            send(client->client_socket, response, strlen(response), 0);
            game_over = 1;
            client->in_game = 0;
            return;
        }
        send(client->client_socket, response, strlen(response), 0);
    }

    if (!game_over) {
        snprintf(response, BUFFER_SIZE, "Game over! The number was %d.\nGame ended. Enter next command.\n", secret);
        send(client->client_socket, response, strlen(response), 0);
    }
    client->in_game = 0;
}

void handle_command(Client *client, const char *command) {
    char response[BUFFER_SIZE];

    // Логирование команды
    log_session(client->authenticated ? client->username : "Unknown", command);

    // Проверка на статус в игре
    if (client->in_game) {
        send(client->client_socket, "You are currently in a game. Please finish the current game first.\n", 64, 0);
        return;
    }

    if (strncmp(command, "ping", 4) == 0) {
        send(client->client_socket, "pong\n", 5, 0);
    } else if (strncmp(command, "server_info", 11) == 0) {
        char hostname[1024];
        gethostname(hostname, sizeof(hostname));
        snprintf(response, BUFFER_SIZE, "Server Info: Hostname: %s\n", hostname);
        send(client->client_socket, response, strlen(response), 0);
    } else if (strncmp(command, "myinfo", 6) == 0) {
        handle_myinfo(client);
    } else if (strncmp(command, "auth", 4) == 0) {
        char username[BUFFER_SIZE], password[BUFFER_SIZE];
        if (sscanf(command + 5, "%s %s", username, password) == 2) {
            authenticate_user(client, username, password);
            log_session(username, "Authenticated");
        } else {
            send(client->client_socket, "Usage: auth <username> <password>\n", 35, 0);
        }
    } else if (strncmp(command, "register", 8) == 0) {
        char username[BUFFER_SIZE], password[BUFFER_SIZE];
        if (sscanf(command + 9, "%s %s", username, password) == 2) {
            register_user(client, username, password);
            log_session(username, "Registered");
        } else {
            send(client->client_socket, "Usage: register <username> <password>\n", 38, 0);
        }
    } else if (strncmp(command, "session_history", 15) == 0) {
        handle_session_history(client);
    } else if (strncmp(command, "game", 4) == 0) {
        if (client->authenticated) {
            handle_game(client);
        } else {
            snprintf(response, BUFFER_SIZE, "Authentication required to play the game. Please log in using 'auth <username> <password>'.\n");
            send(client->client_socket, response, strlen(response), 0);
        }
    } else if (strncmp(command, "help", 4) == 0) {
        snprintf(response, BUFFER_SIZE,
            "Available commands:\n"
            "  - ping: Check server response\n"
            "  - server_info: Get server information\n"
            "  - myinfo: Display your client information\n"
            "  - register <username> <password>: Register a new user\n"
            "  - auth <username> <password>: Authenticate as a registered user\n"
            "  - session_history: View your session history\n"
            "  - game: Start a guessing game (requires authentication)\n"
            "  - exit: Disconnect from the server\n"
            "  - help: Show this list of commands\n");
        send(client->client_socket, response, strlen(response), 0);
    } else if (strncmp(command, "exit", 4) == 0) {
    send(client->client_socket, "Goodbye!\n", 9, 0);

    // Уменьшаем счетчик активных клиентов
    pthread_mutex_lock(&client_count_lock);
    active_clients--;
    pthread_mutex_unlock(&client_count_lock);

    close(client->client_socket);
    free(client);
    pthread_exit(NULL);
}
 else {
        snprintf(response, BUFFER_SIZE, "Unknown command: '%s'. Type 'help' for a list of commands.\n", command);
        send(client->client_socket, response, strlen(response), 0);
    }
}


void *client_handler(void *arg) {
    Client *client = (Client *)arg;
    char buffer[BUFFER_SIZE];

    snprintf(buffer, BUFFER_SIZE,
        "Welcome to the server!\n"
        "Available commands:\n"
        "  - ping: Check server response\n"
        "  - myinfo: Display client info\n"
        "  - server_info: Get server information\n"
        "  - register <username> <password>: Register a new user\n"
        "  - auth <username> <password>: Authenticate as a registered user\n"
        "  - session_history: View session history (requires authentication)\n"
        "  - game: Play a guessing game (requires authentication)\n"
        "  - exit: Disconnect from the server\n");
    send(client->client_socket, buffer, strlen(buffer), 0);

    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_read = read(client->client_socket, buffer, BUFFER_SIZE);
        if (bytes_read <= 0) {
            printf("Client disconnected.\n");

            // Уменьшаем счетчик активных клиентов
            pthread_mutex_lock(&client_count_lock);
            active_clients--;
            pthread_mutex_unlock(&client_count_lock);

            close(client->client_socket);
            free(client);
            pthread_exit(NULL);
        }
        buffer[strcspn(buffer, "\n")] = 0;  // Удаление символа новой строки
        handle_command(client, buffer);
    }
}


int main() {
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        handle_errors("Socket failed");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        handle_errors("Bind failed");
    }

    if (listen(server_fd, 10) < 0) {
        handle_errors("Listen failed");
    }

    printf("Server is running on port %d\n", PORT);

    // Запуск потока для проверки простоя
    pthread_t shutdown_thread;
    if (pthread_create(&shutdown_thread, NULL, idle_shutdown, NULL) != 0) {
        perror("Failed to create shutdown thread");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    pthread_detach(shutdown_thread);

    while (1) {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        // Увеличиваем количество активных клиентов
        pthread_mutex_lock(&client_count_lock);
        active_clients++;
        pthread_mutex_unlock(&client_count_lock);

        Client *client = malloc(sizeof(Client));
        client->client_socket = client_socket;
        client->authenticated = 0;
        client->in_game = 0;
        memset(client->username, 0, BUFFER_SIZE);

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_handler, (void *)client) != 0) {
            perror("Failed to create thread");
            free(client);
            close(client_socket);
            continue;
        }
        pthread_detach(thread_id);
    }

    return 0;
}