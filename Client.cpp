#define _WINSOCK_DEPRECATED_NO_WARNINGS //ubsługa warningów winsoc
#define _CRT_SECURE_NO_WARNINGS //ubsługa warningów pliki
#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER "127.0.0.1" //local
#define PORT 8888 //obojetnie ktory

void ShowCerts(SSL* ssl) //wyswietlanie certyfikatów
{
	X509* cert;
	char* line;
	cert = SSL_get_peer_certificate(ssl); // prosi o komunikat z certyfikatem serweru
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0); //subject
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert); // czysci pamiec certyfikatu
	}
	else
		printf("Info: No client certificates configured.\n");
}


int main()
{
	WSADATA wsa_data;
	SSL_CTX* ctx; 
	SSL* ssl;
	// Gniazdo
	SOCKET sock;
	// Struktura z informacjami o adresie serwera
	struct sockaddr_in server_addr;
	// Inicjalizacja Winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
	{
		printf("WSAStartup failed.\n");
		return 1;
	}

	// Inicjalizacja OpenSSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();


	// Tworzenie gniazda
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket failed.\n");
		WSACleanup();
		return 1;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(SERVER);
	server_addr.sin_port = htons(PORT);

	// Łączenie z serwerem
	if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("connect failed.\n");
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	 ctx = SSL_CTX_new(TLS_client_method()); //tworzenie contextu ssl, metoda tls

	if (!ctx)
	{
		printf("SSL_CTX_new failed.\n");
		closesocket(sock);
		WSACleanup(); //czyszczenie
		return 1;
	}

	// Wczytanie certyfikatu
	if (!SSL_CTX_use_certificate_file(ctx, "client.crt", SSL_FILETYPE_PEM))
	{
		printf("Could not load certificate.\n");
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// Wczytanie klucza prywatnego
	if (!SSL_CTX_use_PrivateKey_file(ctx, "client.key", SSL_FILETYPE_PEM))
	{
		printf("Could not load private key.\n");
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	//sprawdzenie czy pasuje/jest odpowiedni klucz do certyfikatu
	if (!SSL_CTX_check_private_key(ctx)) {
		printf("Private key does not match the certificate");
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// Tworzenie struktury SSL dla połączenia
	ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("SSL_new failed.\n");
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}
	// Przypisanie gniazda do struktury SSL
	if (!SSL_set_fd(ssl, sock)) {
		printf("SSL_set_fd failed.\n");
		SSL_CTX_free(ctx);
		SSL_free(ssl);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	int ret;
	// Nawiązywanie połączenia SSL
	if (ret = SSL_connect(ssl) != 1)
	{
		printf("SSL_connect failed.Error %d\n", SSL_get_error(ssl, ret));
		SSL_free(ssl);
		SSL_CTX_free(ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	ShowCerts(ssl); // wypisywanie certyfikatu

	// Wysyłanie certyfikatu klienta
	char buffer[1025];
	// Pętla obsługi komend
	while (1)
	{
		// Wczytywanie komendy od użytkownika
		printf("Enter command: ");
		fgets(buffer, sizeof(buffer), stdin);

		if (buffer[0] == '\n')
			break;

		// Obsługa komendy 'send'
		if (strncmp(buffer, "send", 4) == 0)
		{
			FILE* file = fopen("plik.txt", "rb");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku");
				break;
			}

			// Wysyłanie komendy do serwera
			if (SSL_write(ssl, "send", 4) <= 0)
			{
				printf("SSL_write failed.\n");
				break;
			}
			int n;
			// Pętla wysyłająca plik po 1024 bajty
			while ((n = fread(buffer, 1, 1024, file)) > 0) { //zczytuje dane z pliku
				int bytes_sent = SSL_write(ssl, buffer, n); //wysyła plik na serwer
				if (bytes_sent < 0) { //czy bład podczas wysyłania
					perror("Błąd przy wysyłaniu pliku");
					fclose(file);
					SSL_CTX_free(ctx);
					SSL_free(ssl);
					closesocket(sock);
					WSACleanup();
					return 1;
				}
			}
			SSL_write(ssl, "END_OF_FILE", 11); //informacja o końcu pliku
		}
		// Obsługa komendy 'read'
		else if (strncmp(buffer, "read", 4) == 0)
		{
			// Wysyłanie komendy do serwera
			if (SSL_write(ssl, "read", 4) <= 0)
			{
				printf("SSL_write failed.\n");
				break;
			}

			//wczytywanie wiadomości do pliku
			FILE* file = fopen("plik_z_serwera.txt", "w");
			if (file == NULL) {
				perror("Nie udało się otworzyć pliku");
				break;
			}

			while (1) {

				int size = SSL_read(ssl, buffer, sizeof(buffer) - 1);
				// Odbieranie danych od serwera
				if (size <= 0)
				{
					fclose(file);
					break;
				}
				// Sprawdzanie, czy otrzymano znak konca wysylania danych
				if (strncmp(buffer, "END_OF_FILE", 11) == 0) //sprawdza zakonczenie przesylania
				{
					fclose(file);
					break;
				}

				buffer[size] = '\0'; 
				if (fwrite(buffer, 1, size, file) != size) {
					perror("Nie udało się zapisać danych do pliku");
					SSL_CTX_free(ctx);
					SSL_free(ssl);
					closesocket(sock);
					WSACleanup();
					return 1;
				}
			}
			printf("\n");
		}
		else {
			char* ptr = strchr(buffer, '\0');
			int index = ptr - buffer;

			int bytes_sent = SSL_write(ssl, buffer, index);
			if (bytes_sent < 0) {
				perror("Błąd wysyłania komendy");
				break;
			}
		}
	}
	// Zakończenie połączenia SSL
	SSL_shutdown(ssl);

	// Zwalnianie zasobów
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	closesocket(sock);

	// Zakończenie pracy Winsock
	WSACleanup();

	return 0;
}

