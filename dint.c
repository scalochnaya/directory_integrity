#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <syslog.h>

#define MAX_PATH_LENGTH 1024
#define SHA256_LENGTH 64
#define ERROR_CODE -1
#define NORMAL_CODE 0
#define MAX_LOGMSG_LENGTH 128


void writeToSyslog(int status, char* message)
{
	// Write info to syslog
	openlog("DINT", LOG_PID | LOG_CONS, LOG_USER);
	if (status == NORMAL_CODE)
		syslog(LOG_INFO, message);
	else syslog(LOG_ERR, message);
	closelog();
}

void calculateHashOfFile(char* file, FILE* outfile)
{
	// Calculating SHA-256 hash
        FILE* fil = fopen(file, "rb");
	if (fil == NULL)
	{
		printf("[X] Error opening file %s\n", file);
		exit(ERROR_CODE);
	}
        EVP_MD_CTX* mdctx;
        mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);

        struct stat st;
        fstat(fileno(fil), &st);
        size_t fileSize = st.st_size;

        unsigned char* data = malloc(fileSize);
        size_t bytes_read;
        while ((bytes_read = fread(data, 1, sizeof(data), fil)) > 0)
	{
              	if (!EVP_DigestUpdate(mdctx, data, bytes_read))
		{
                        printf("[X] Error updating EVP_DigestUpdate\n");
                        EVP_MD_CTX_free(mdctx);
                        fclose(fil);
                        exit(ERROR_CODE);
                }
        }
	free(data);

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        if (!EVP_DigestFinal_ex(mdctx, md_value, &md_len))
	{
        	printf("[X] Error finalizing EVP_DigestFinal_ex\n");
                EVP_MD_CTX_free(mdctx);
                fclose(fil);
                exit(ERROR_CODE);
        }

        EVP_MD_CTX_free(mdctx);
        fclose(fil);

	// Writing hash to file
        for (int i = 0; i < md_len; i++)
                fprintf(outfile, "%02x", md_value[i]);
	fprintf(outfile, "\n");

	return;
}

int checkDirectoryIntegrity(char* directory, FILE* list, FILE* templist)
{
	int status = 1;
        int i = 0;

        char* currFile;
	char* tempFile;
	char* hash;
	char* newHash;

	while(fgetc(list) != EOF)
	{
        	currFile = malloc(MAX_PATH_LENGTH);
		currFile[0] = '/';
        	i = 1;

		// Get current file name
        	while ((currFile[i] = fgetc(list)) != ' ') i++;
        	currFile[i] = 0;

        	i = 0;
        	hash = malloc(SHA256_LENGTH);
		// Get hash of file from list
        	while ((hash[i] = fgetc(list)) != '\n') i++;
        	hash[i] = 0;

		tempFile = malloc(MAX_PATH_LENGTH);
		i = 1;
		// Get dir name from temporary file
		if (fgetc(templist) == EOF)
		{
			char* msg = malloc(MAX_LOGMSG_LENGTH);
			sprintf(msg, "Problem with file: %s", currFile);
			writeToSyslog(ERROR_CODE, msg);
			free(msg);
			return 0;
		}
		tempFile[0] = '/';
		while ((tempFile[i] = fgetc(templist)) != ' ') i++;
		tempFile[i] = 0;

		newHash = malloc(SHA256_LENGTH);
		i = 0;
		// Get current file hash
		while ((newHash[i] = fgetc(templist)) != '\n') i++;
		newHash[i] = 0;

		if (strcmp(currFile, tempFile) == 0 && strcmp(hash, newHash) == 0)
			continue;
		else
		{
			char* msg = malloc(MAX_LOGMSG_LENGTH);
			sprintf(msg, "Differences between %s ans %s files", currFile, tempFile);
			writeToSyslog(ERROR_CODE, msg);
			free(msg);
			status = 0;
		}

        	free(currFile);
		free(tempFile);
		free(hash);
		free(newHash);
	}
	if (fgetc(templist) != EOF)
	{
                writeToSyslog(ERROR_CODE, "Now directory has more files");
                status = 0;
	}

	remove("temp_list");
	return status;
}


void addDirectoryToList(char* directory, FILE* outfile)
{
	DIR* dir_handle;
	struct dirent* entry;

	if (!(dir_handle = opendir(directory)))
	{
		printf("[X] Failed to open directory. Is the name of directory correct?\n");
		exit(ERROR_CODE);
	}

	while ((entry = readdir(dir_handle)) != NULL)
	{
		if (entry->d_name[0] == '.')
			continue;
		char* path = malloc(strlen(directory) + strlen(entry->d_name) + 2);
		sprintf(path, "%s/%s", directory, entry->d_name);

		if (entry->d_type == DT_DIR)
		{
			addDirectoryToList(path, outfile);
		}
		else
		{
			fprintf(outfile, "%s ", path);
			calculateHashOfFile(path, outfile);
		}
		free(path);
	}
	closedir(dir_handle);
}


int main()
{
	printf("\n\t\tDIRECTORY INTEGRITY\n\n");
        int chosenAction;
        printf(" Choose an action:\n[1] to add directory to dint_list\n[2] to check integrity of directory from dint_list file\n[3] to exit program\n[1/2/3]: ");
        scanf("%d", &chosenAction);
	printf("\n");

	switch (chosenAction)
	{
	case 1:
                printf(" Enter directory: ");
                char* dir;
                dir = malloc(MAX_PATH_LENGTH);
                scanf("%s", dir);
		printf("[*] Processing...\n");

                FILE* outfile = fopen("dint_list", "w");
                fprintf(outfile, "%s\n", dir);

                addDirectoryToList(dir, outfile);
                fclose(outfile);
		char* message = malloc(MAX_LOGMSG_LENGTH);
                sprintf(message, "Successfully added directory %s to dint_list", dir);
		free(dir);
		printf("[*] %s\n", message);
		writeToSyslog(NORMAL_CODE, message);
		free(message);
		break;

	case 2:
		printf(" Path to list (enter [A] to use standart dint_list): ");
		char* pathToList = malloc(MAX_PATH_LENGTH);
		scanf("%s", pathToList);

		FILE* fromlist_outfile;
		if (strcmp(pathToList, "A") == 0)
			fromlist_outfile = fopen("dint_list", "r");
		else fromlist_outfile = fopen(pathToList, "r");
		free(pathToList);

		if (fromlist_outfile == NULL)
		{
			printf("[X] Error opening file\n");
			exit(ERROR_CODE);
		}

		char* fromlist_dir = malloc(MAX_PATH_LENGTH);
		fgets(fromlist_dir, MAX_PATH_LENGTH, fromlist_outfile);
		fromlist_dir[strlen(fromlist_dir) - 1] = 0;
		// what if dint_list empty?
		printf("[*] Checking integrity of: %s\n", fromlist_dir);
		printf("[*] Processing...\n");

		FILE* temp_file = fopen("temp_list", "w");
		addDirectoryToList(fromlist_dir, temp_file);
		fclose(temp_file);
		temp_file = fopen("temp_list", "r");

		char* message_checking = malloc(MAX_LOGMSG_LENGTH);
		if (checkDirectoryIntegrity(fromlist_dir, fromlist_outfile, temp_file) == 1)
		{
			sprintf(message_checking, "Integrity of %s certified", fromlist_dir);
			writeToSyslog(NORMAL_CODE, message_checking);
			printf("[*] %s\n", message_checking);
		}
		else
		{
			sprintf(message_checking, "Violation of integrity control: %s", fromlist_dir);
			writeToSyslog(ERROR_CODE, message_checking);
			printf("[X] %s\n", message_checking);
		}
		free(message_checking);

		free(fromlist_dir);
		fclose(fromlist_outfile);
		fclose(temp_file);

		break;
	case 3:
		printf("[*] Exiting program...\n");
		exit(NORMAL_CODE);
	default:
		printf("[X] Invalid operation\n[*] Exiting program...\n");
		exit(ERROR_CODE);
	}

	printf("\n");
	return NORMAL_CODE;
}
