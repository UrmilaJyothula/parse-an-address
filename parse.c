#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>


#define NUMPROP 6
#define BUFLEN 20
#define elements_in(x)   (sizeof(x)/sizeof(x[0]))

int digits_only(const char* s);
char* nextpart(const char* str, char* buffer);
//bool BACnet_parse(const char* str, uint8_t* bactype, rbs_remote_device_t* dev, uint32_t* oi, BACnetApplicationTag_t tag, uint32_t* pi, uint32_t* ai);
int digits_only(const char* s);
int findIPMAP(char* s);
int findHexaValidity(char* s);
int is_hexa(char* s);
int is_valid_ip(char* s);
int Devno(char* s);
int FindMSTPMAC(char* s);
int appdatatype(char* s);

char* nextpart(const char* str, char* buffer)
{
	char* next;
	int len;

	int i = 0;
	//char Token[NUMPROP][BUFLEN];

	next = strchr(str, '|');

	if (next) {
		len = next - str;
	}
	else {
		len = strlen(str);
	}

	if (len >= BUFLEN) {
		buffer[0] = 0;
		return NULL;
	}
	else {
		memcpy(buffer, str, len);
		buffer[len] = 0;
		//next + 1;
	}

	return next ? next + 1 : NULL;

}

	

enum BACnetApplicationTag_enum
{
	rbs_bat__Null = 0,
	rbs_bat__Boolean = 1,
	rbs_bat__Unsigned_Integer = 2,
	rbs_bat__Signed_Integer = 3,
	rbs_bat__Real = 4,
	rbs_bat__Double = 5,
	rbs_bat__Octet_String = 6,
	rbs_bat__Character_String = 7,
	rbs_bat__Bit_String = 8,
	rbs_bat__Enumerated = 9,
	rbs_bat__Date = 10,
	rbs_bat__Time = 11,
	rbs_bat__BACnetObjectIdentifier = 12,
	rbs_bat__Reserved1 = 13,
	rbs_bat__Reserved2 = 14,
	rbs_bat__Reserved3 = 15
};


typedef enum BACnetApplicationTag_enum    BACnetApplicationTag_t;

enum rbs_datalink_id_enum
{
#if(RBS_DATALINK_MSTP_COUNT>0)
	rbs_datalink_mstp1,
#if(RBS_DATALINK_MSTP_COUNT>1)
	rbs_datalink_mstp2,
#if(RBS_DATALINK_MSTP_COUNT>2)
	rbs_datalink_mstp3,
#if(RBS_DATALINK_MSTP_COUNT>3)
	rbs_datalink_mstp4,
#if(RBS_DATALINK_MSTP_COUNT>4)
	rbs_datalink_mstp5,
#endif
#endif
#endif
#endif
#endif
#if(RBS_DATALINK_IP_COUNT>0)
	rbs_datalink_ip1,
#if(RBS_DATALINK_IP_COUNT>1)
	rbs_datalink_ip2,
#if(RBS_DATALINK_IP_COUNT>2)
	rbs_datalink_ip3,
#if(RBS_DATALINK_IP_COUNT>3)
	rbs_datalink_ip4,
#endif
#endif
#endif
#endif
	rbs_datalink_any,
	rbs_datalink_disabled,
	rbs_datalink_NULL = rbs_datalink_disabled
};


#if ( ( RBS_DATALINK_MSTP_COUNT + RBS_DATALINK_IP_COUNT ) == 0 )
#define RBS_DATALINK_VIRTUAL_COUNT    1
#define RBS_DATALINK_COUNT            RBS_DATALINK_VIRTUAL_COUNT
#else
#define RBS_DATALINK_COUNT ( RBS_DATALINK_MSTP_COUNT + RBS_DATALINK_IP_COUNT /*+ RBS_DATALINK_ETHERNET_COUNT */)
#define RBS_DATALINK_VIRTUAL_COUNT    0
#define RBS_MAX_NETWORK_PORTS             RBS_DATALINK_COUNT
#define RBS_NETWORK_PORT_PREFIX_MSTP      "mstp_port_%d"
#define RBS_NETWORK_PORT_PREFIX_IP        "ipv4_port_%d"
#endif

#define RBS_FRAME_META_DATALINK_ANY  rbs_datalink_any


typedef enum rbs_datalink_id_enum  rbs_datalink_id_t;

struct  rbs_local_address_struct
{
	uint8_t     mac_len;
	uint8_t     mac_oct[10];
};

typedef struct rbs_local_address_struct     rbs_local_address_t;

struct  rbs_remote_address_struct
{
	uint16_t              net;
	rbs_local_address_t   mac;
};

typedef struct rbs_remote_address_struct    rbs_remote_address_t;

struct rbs_remote_device_struct
{

	rbs_remote_address_t                remote_address;
	rbs_datalink_id_t                   datalink_id;
	rbs_local_address_t                 local_address;
	unsigned                            device_instance_number;
	unsigned                            static_binding : 1; 

};

typedef struct rbs_remote_device_struct  rbs_remote_device_t;

caller()
{
	rbs_remote_device_t* rd;
}

bool BACnet_parse(const char* str, uint8_t* bactype, rbs_remote_device_t* rd, uint32_t* oi, BACnetApplicationTag_t* tag, uint32_t* pi, uint32_t* ai)
{

	char buffer[BUFLEN];

	*bactype = 0;
	*oi = ~0;

	const char* next = str;
	char* cend;

	//printf("Invoke id : %d", rd->invokeid);
	//printf(" max apdu : %d", rd->max_apdu_accepted);

	next = nextpart(next, buffer);

	if (strcmp(buffer, "B") == 0) {

		// BACnet. Parse the device specifier
		if (next == NULL) {
			return false;
			next = nextpart(next, buffer);
		}
		// Todo Do it

		// It is legal to stop here
		if (next == NULL)
			return true;
		//dev
		next = nextpart(next, buffer);
		if (rd != 0)
			//if (*cend != '|' && *cend != 0)
				return false;

			if (next == NULL)
				return true; // or false, chech grammar

			// Object id
		next = nextpart(next, buffer);
		*oi = strtoul(buffer, &cend, 10);
		if (*cend != '|' && *cend != 0)
			return false;

		if (next == NULL)
			return true; // or false, chech grammar
			//tag
		next = nextpart(next, buffer);
		*tag = strtoul(buffer, &cend, 10);
		if (*cend != '|' && *cend != 0)
			return false;

		if (next == NULL)
			return true;

		// Property id
		next = nextpart(next, buffer);
		*pi = strtoul(buffer, &cend, 10);
		if (*cend != '|' && *cend != 0)
			return false;

		if (next == NULL)
			return true;

		// ai
		next = nextpart(next, buffer);
		*ai = strtoul(buffer, &cend, 10);
		if (*cend != '|' && *cend != 0)
			return false;

		if (next == NULL)
			return true;
	}

	else
		return false;
}

int digits_only(const char* s)
{
	while (*s) {
		if (isdigit(*s++) == 0)
			return 0;
	}

	return 1;
}

int typeValidity(char* s) {

	char first = s[0];

	switch (first) {

	case 'S':
		return findHexaValidity(s);
		break;

	case 'M':
		return FindMSTPMAC(s);
		break;

	case 'D':
		return Devno(s);
		break;

	case 'I':
		return findIPMAP(s);
		break;

	default:
		return digits_only(s);
		break;

	}

}

int findIPMAP(char* s) {

	char remaining[30];
	char subToll[2][20] = { '\0', '\0' };
	char* toll;
	char c[2] = "@";
	//int number;

	memcpy(remaining, s + 2, strlen(s) + 1);

	/* get the first token */
	toll = strtok(remaining, c);

	/* walk through other tokens */

	int i = 0;
	while (toll != NULL) {
		strcpy(subToll[i], toll);
		toll = strtok(NULL, c);
		i++;
	}

	if (is_valid_ip(subToll[0])) {

		if (subToll[1] && !digits_only(subToll[1])) {

			if (strstr(subToll[1], "mstp") == NULL) {
				return 0;
			}

		}

	}
	else {
		return 0;
	}

	return 1;

}

int findHexaValidity(char* s) {

	char remaining[20];
	char subToll[2][20] = { '\0', '\0' };
	char* toll;
	char c[2] = "@";

	memcpy(remaining, s + 1, strlen(s) + 1);

	/* get the first token */
	toll = strtok(remaining, c);

	/* walk through other tokens */

	int i = 0;
	while (toll != NULL) {
		strcpy(subToll[i], toll);
		toll = strtok(NULL, c);
		i++;
	}


	if ((strlen(subToll[0]) >= 2) && (strlen(subToll[0]) <= 14) && is_hexa(subToll[0])) {

		if (subToll[1] && !digits_only(subToll[1])) {

			if (strstr(subToll[1], "mstp") == NULL) {
				return 0;
			}

		}

	}
	else {
		return 0;
	}

	return 1;
}

int is_hexa(char* s) {

	for (int i = 0; i < strlen(s); i++) {

		if (!isxdigit(s[i])) {
			return 0;
			break;
		}

	}
	return 1;
}

int is_valid_ip(char* s) {

	char* toll;
	char c[2] = ".";
	/* get the first token */
	toll = strtok(s, c);

	/* walk through other tokens */

	int i = 0;
	while (toll != NULL) {

		if (!digits_only(toll)) {
			return 0;
			break;
		}

		toll = strtok(NULL, c);
		i++;

	}

	if (i != 4) {
		return 0;
	}

	return 1;
}

int Devno(char* s) {

	char remaining[30];

	memcpy(remaining, s + 1, strlen(s) + 1);
	//printf("%s ", remaining);

	if ((atoi(remaining)) >= 0 && (atoi(remaining)) <= 12) {
		return 1;
	}
	else
	{
		return 0;
	}

}

int FindMSTPMAC(char* s) {

	char remaining[30];

	memcpy(remaining, s + 1, strlen(s) + 1);
	//printf("%s ", remaining);

	if ((atoi(remaining)) >= 0 && (atoi(remaining)) <= 254) {
		return 1;
	}
	else
	{
		return 0;
	}

}

int appdatatype(char* s)
{
	if (atoi(s) >= 0 && atoi(s) <= 12)
	{
		return 1;

	}
	else
	{
		return 0;
	}
}

int Bactype(char* s)
{
	if (*s == 'B')
	{
		return 1;

	}
	else
	{
		return 0;
	}
}



int main(void)
{
	uint8_t bactype;
	uint32_t oi;
	uint32_t pi;
	uint32_t ai;
	rbs_remote_device_t rd;


	char remaining[100];
	char subTok[7][20] = { '\0', '\0', '\0', '\0', '\0', '\0', '\0' };
	char* toll;
	char c[2] = "|";


	//memset(&rd, 0, sizeof(rd));
	char str[] = "B|10011|8|11|0|52|5";
	memcpy(remaining, str, strlen(str) + 1);
	toll = strtok(remaining, c);
	int j = 0;
	while (toll != NULL) {
		strcpy(subTok[j], toll);
		toll = strtok(NULL, c);
		//printf("%s\n", subTok[j]);
		j++;
	}

	printf("%d\n", typeValidity(subTok[1]));
	printf("%d..", Bactype(subTok[0]));
	printf("%d\n", appdatatype(subTok[3]));

	BACnetApplicationTag_t tag = atoi(subTok[3]);


	char str2[] = "B|S33xalsnxkalsnx";
	char str3[] = "B|M90||10|529496725";
	char str5[] = "B|IP1.2.3.4@999|123|14|5294967295|55555"; //error 
	char str4[] = "B|IP1.2.3.4@999|1220000|14|5294967295|55555";

	//memset(&rd, 0, sizeof(rd));
	BACnet_parse(str, &bactype, &rd, &oi, &tag, &pi, &ai);
	memset(&rd, 0, sizeof(rd));
	BACnet_parse(str2, &bactype, &rd, &oi, &tag, &pi, &ai);
	memset(&rd, 0, sizeof(rd));
	BACnet_parse(str3, &bactype, &rd, &oi, &tag, &pi, &ai);
	memset(&rd, 0, sizeof(rd));
	BACnet_parse(str4, &bactype, &rd, &oi, &tag, &pi, &ai);

	char buffer[BUFLEN];
	int i;
	char* next = str;

	char Token[NUMPROP][BUFLEN];

	for (i = 0; i < elements_in(Token); i++) {
		next = nextpart(next, buffer);
		strcpy(Token[i], buffer);
		if (next == NULL)
			break;
	}
	printf((*Token[0] == 'B') ? "True\n" : "False\n");

}




