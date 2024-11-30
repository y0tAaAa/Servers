
### Server Features

The server provides the following functionalities for connected clients:

- **registration:**  
  Allows a client to register a new user. The client provides a username and password, which are stored in the `users.txt` file in hashed form.
  
- **authentication:**  
  Authenticates a client by verifying the provided username and password against the `users.txt` file. Authentication is required to use certain commands.

- **myinfo:**  
  Displays client-specific information, including the client's IP address, port, system information, and current time. Requires authentication.

- **server_info:**  
  Displays server information, including the hostname.

- **ping:**  
  Tests server responsiveness. The server replies with "pong".

- **game:**  
  Starts a "Guess the Number" game. The client specifies a range and tries to guess a randomly generated number within that range. The number of attempts is limited. Requires authentication.

- **exit:**  
  Disconnects the client from the server.

- **session_history:**  
  Retrieves information about previous sessions of the authenticated user. Requires authentication.

- **help:**  
  Provides a list of available commands and their descriptions.

---

### Server Operation

The server uses a multithreaded approach to handle multiple client connections simultaneously. Each client request is processed in a separate thread, allowing parallel interactions with multiple users.

Key operations include:
- **Idle shutdown:** The server shuts down automatically if no clients are connected for 60 seconds.
- **User registration:** Stores usernames and hashed passwords in the `users.txt` file for future authentication.
- **User authentication:** Verifies usernames and hashed passwords against stored data in the `users.txt` file. Passwords are hashed using SHA-256 for added security.
- **Brute-force protection:** Limits the number of failed login attempts. If the limit is exceeded, the user is temporarily locked out for 60 seconds.
- **Session logging:** Records session information, including commands used by authenticated users, in the `sessions.txt` file.

---

### Client Functionality

The client application connects to the server and allows the user to interact using the following commands:
- **registration:** Registers a new user with the server.
- **authentication:** Authenticates an existing user.
- **ping:** Tests connectivity with the server.
- **myinfo:** Retrieves client-specific information.
- **server_info:** Displays server details.
- **game:** Starts and plays the "Guess the Number" game.
- **session_history:** Retrieves session history for the authenticated user.
- **help:** Displays the list of available commands.
- **exit:** Disconnects from the server.

The client also handles additional logic, such as:
- Receiving and acknowledging session history records.
- Handling the "Guess the Number" game logic, including user input and server response validation.

---

### File Structure

- **`server.c`:**  
  The main server file containing all the code for handling client connections and processing commands.

- **`client.c`:**  
  The client-side application for connecting to the server and sending commands.

- **`users.txt`:**  
  Stores registered users' data. Passwords are stored as hashed strings for enhanced security.

- **`sessions.txt`:**  
  Logs client session information, including successful and failed authentication attempts, as well as executed commands.

---

### Usage Instructions

1. **Compile the server:**  
   Use the following command to compile the server:
   ```bash
   gcc server.c -o server -pthread -lcrypto -lssl -lm
   ```

2. **Compile the client:**  
   Use the following command to compile the client:
   ```bash
   gcc client.c -o client
   ```

3. **Run the server:**  
   Start the server with:
   ```bash
   ./server
   ```

4. **Connect to the server:**  
   Clients can connect using:
   - The provided client application:  
     ```bash
     ./client <server-ip-address> <port>
     ```
   - `telnet` or any other TCP client, specifying the server IP address and port (default is 9090).

---

### Important Notes

- **Password Security:**  
  User passwords are hashed before being stored in `users.txt`, ensuring secure storage.

- **Brute-force Protection:**  
  The server limits login attempts to prevent brute-force attacks. Exceeding the limit temporarily locks the user account.

- **Authentication Required:**  
  Commands like `myinfo`, `session_history`, and `game` are only accessible after successful authentication.

- **Idle Server Shutdown:**  
  The server automatically shuts down after 60 seconds of inactivity (no connected clients).

- **Session Logging:**  
  All client commands and activities are logged for authenticated users.
