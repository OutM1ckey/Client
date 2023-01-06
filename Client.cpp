﻿#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER "127.0.0.1"
#define PORT 8888

void ShowCerts(SSL* ssl)
{
	X509* cert;
	char* line;
	cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
	if (cert != NULL)
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);       /* free the malloc'ed string */
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);       /* free the malloc'ed string */
		X509_free(cert);     /* free the malloc'ed certificate copy */
	}
	else
		printf("Info: No client certificates configured.\n");
}


int main()
{
	// Inicjalizacja Winsock
	WSADATA wsa_data;
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
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("socket failed.\n");
		WSACleanup();
		return 1;
	}

	// Struktura z informacjami o adresie serwera
	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(PORT);

	// Łączenie z serwerem
	if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("connect failed.\n");
		closesocket(sock);
		WSACleanup();
		return 1;
	}	
	
	SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());

	if (!ssl_ctx)
	{
		printf("SSL_CTX_new failed.\n");
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	// Wczytanie certyfikatu
	if (!SSL_CTX_use_certificate_file(ssl_ctx, "client.crt", SSL_FILETYPE_PEM))
	{
		printf("Could not load certificate.\n");
		return 1;
	}

	// Wczytanie klucza prywatnego
	if (!SSL_CTX_use_PrivateKey_file(ssl_ctx, "client.key", SSL_FILETYPE_PEM))
	{
		printf("Could not load private key.\n");
		return 1;
	}

	if (!SSL_CTX_check_private_key(ssl_ctx)) {
		printf("Private key does not match the certificate");
		return 1;
	}

	// Tworzenie struktury SSL dla połączenia
	SSL* ssl = SSL_new(ssl_ctx);
	if (!ssl)
	{
		printf("SSL_new failed.\n");
		return 1;
	}
	// Przypisanie gniazda do struktury SSL
	SSL_set_fd(ssl, sock);
	int ret;
	// Nawiązywanie połączenia SSL
	if (ret = SSL_connect(ssl) != 1)
	{
		printf("SSL_connect failed.Error %d\n",SSL_get_error(ssl,ret));
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

	ShowCerts(ssl);

	// Wysyłanie certyfikatu klienta
	char buffer[1025];
	if (SSL_write(ssl, buffer, sizeof(buffer)) <= 0)
	{
		printf("SSL_write failed.\n");
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		closesocket(sock);
		WSACleanup();
		return 1;
	}

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
				exit(1);
			}

			// Wysyłanie komendy do serwera
			if (SSL_write(ssl, "send", 4) <= 0)
			{
				printf("SSL_write failed.\n");
				break;
			}
			int n;
			// Pętla wysyłająca plik po 1024 bajty
			while ((n = fread(buffer, 1, 1024, file)) > 0) {
				int bytes_sent = SSL_write(ssl, buffer, n);
				if (bytes_sent < 0) {
					perror("Błąd przy wysyłaniu pliku");
					exit(1);
				}
			}
			SSL_write(ssl, "END_OF_FILE", 11);
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
			while (1) {
				int size = SSL_read(ssl, buffer, sizeof(buffer)-1);
				// Odbieranie danych od serwera
				if (size <= 0)
				{
					break;
				}
				// Sprawdzanie, czy otrzymano znak konca wysylania danych
				if (strncmp(buffer, "END_OF_FILE", 11) == 0)
				{
					break;
				}
				buffer[size] = '\0';
				printf("%s", buffer);
			}
			printf("\n");
			
		}
	}
	// Zakończenie połączenia SSL
	SSL_shutdown(ssl);

	// Zwalnianie zasobów
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);
	closesocket(sock);

	// Zakończenie pracy Winsock
	WSACleanup();

	return 0;

}

int main2()
{
	// Inicjalizacja Winsock
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
	{
		printf("WSAStartup failed.\n");
		return 1;
	}

	// Utworzenie gniazda
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock == INVALID_SOCKET)
	{
		printf("Could not create socket.\n");
		return 1;
	}

	// Przygotowanie struktury adresowej
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = inet_addr(SERVER);

	// Łączenie się z serwerem
	if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
	{
		printf("Connect failed.\n");
		return 1;
	}

	// Inicjalizacja OpenSSL
	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());

	// Wczytanie certyfikatu
	if (!SSL_CTX_use_certificate_file(ctx, "client_cert.pem", SSL_FILETYPE_PEM))
	{
		printf("Could not load certificate.\n");
		return 1;
	}

	// Wczytanie klucza prywatnego
	if (!SSL_CTX_use_PrivateKey_file(ctx, "client_key.pem", SSL_FILETYPE_PEM))
	{
		printf("Could not load private key.\n");
		return 1;
	}

	// Tworzenie struktury SSL dla połączenia
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("SSL_new failed.\n");
		return 1;
	}

	// Przypisanie gniazda do struktury SSL
	SSL_set_fd(ssl, sock);

	// Tworzenie struktury SSL dla połączenia
	if (!ssl)
	{
		printf("SSL_new failed.\n");
		return 1;
	}

	// Przypisanie gniazda do struktury SSL
	SSL_set_fd(ssl, sock);

	// Łączenie się z serwerem przez SSL
	if (SSL_connect(ssl) <= 0)
	{
		printf("SSL_connect failed.\n");
		return 1;
	}
	else
	{
		printf("Connected to %s:%d.\n", SERVER, PORT);

		// Wysyłanie danych do serwera
		char buffer[1024] = "Hello, Server!";
		int ret = SSL_write(ssl, buffer, sizeof(buffer));
		if (ret <= 0)
		{
			printf("SSL_write failed.\n");
			return 1;
		}

		// Odbieranie danych od serwera
		ret = SSL_read(ssl, buffer, sizeof(buffer));
		if (ret <= 0)
		{
			printf("SSL_read failed.\n");
			return 1;
		}

		printf("Received: %s\n", buffer);

		// Zamykanie połączenia i zwalnianie zasobów
		SSL_shutdown(ssl);
		SSL_free(ssl);
		closesocket(sock);

		// Zakończenie pracy Winsock
		WSACleanup();

		return 0;
	}
}
