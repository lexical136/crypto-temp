#include <stdint.h>
#include <stdio.h>

uint32_t k3s[10000][4];
uint32_t k2s[10000][4];
uint32_t k1s[10000][4];
uint32_t k0s[10000][4];
uint32_t k4s[10000][4];
uint32_t k5s[10000][4];

//////////////////////CODE from FEAL.C on loop //////////////////////////
#define WORD32 unsigned int
#define BYTE   unsigned char

#define ROUNDS 4

#define ROT2(x) (((x)<<2) | ((x)>>6))

#define G0(a,b) (ROT2((BYTE)((a)+(b))))
#define G1(a,b) (ROT2((BYTE)((a)+(b)+1)))

static WORD32 pack32(BYTE* b)
{ /* pack 4 bytes into a 32-bit Word */
	return (WORD32)b[3] | ((WORD32)b[2] << 8) | ((WORD32)b[1] << 16) | ((WORD32)b[0] << 24);
}

static void unpack32(WORD32 a, BYTE* b)
{ /* unpack bytes from a 32-bit word */
	b[0] = (BYTE)(a >> 24);
	b[1] = (BYTE)(a >> 16);
	b[2] = (BYTE)(a >> 8);
	b[3] = (BYTE)a;
}

WORD32 f(WORD32 input)
{
	BYTE x[4], y[4];
	unpack32(input, x);
	y[1] = G1(x[1] ^ x[0], x[2] ^ x[3]);
	y[0] = G0(x[0], y[1]);
	y[2] = G0(y[1], x[2] ^ x[3]);
	y[3] = G1(y[2], x[3]);
	return pack32(y);
}
//////////////////////////////////////////////////////////

//Decrypts round 4
uint64_t decrypt1round(uint64_t cipher, uint32_t roundKey) {
	//printf("Input cipher = %llx, roundKey = %x\n", cipher, roundKey);
	uint32_t Right0 = cipher & 0b11111111111111111111111111111111;  //Fine
	uint64_t CipherTemp = cipher >> 32;
	uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine
	uint32_t temp = Left0;

	Right0 = Right0 ^ Left0;
	temp = Right0 ^ roundKey;
	temp = f(temp);
	Left0 = Left0 ^ temp;

	temp = Right0;
	Right0 = Left0;
	Left0 = temp;

	//printf("Cipher = %lx%lx\n", Left0, Right0);
	CipherTemp = (uint64_t)Left0 << 32;
	CipherTemp = CipherTemp + Right0;
	//printf("Cipher = %llx\n", CipherTemp);

	return CipherTemp;
}

//Decrypts rounds 2 and 3
uint64_t decrypt_other_rounds(uint64_t cipher, uint32_t roundKey) {
	//printf("Input cipher = %llx, roundKey = %x\n", cipher, roundKey);
	uint32_t Right0 = cipher & 0b11111111111111111111111111111111;  //Fine
	uint64_t CipherTemp = cipher >> 32;
	uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine
	uint32_t temp = Left0;

	//Right0 = Right0 ^ Left0;
	temp = Right0 ^ roundKey;
	temp = f(temp);
	Left0 = Left0 ^ temp;

	temp = Right0;
	Right0 = Left0;
	Left0 = temp;

	//printf("Cipher = %lx%lx\n", Left0, Right0);
	CipherTemp = (uint64_t)Left0 << 32;
	CipherTemp = CipherTemp + Right0;
	//printf("Cipher = %llx\n", CipherTemp);

	return CipherTemp;
}

//Decrypts round 1
uint64_t decrypt_last_round(uint64_t cipher, uint32_t roundKey) {
	//printf("Input cipher = %llx, roundKey = %x\n", cipher, roundKey);
	uint32_t Right0 = cipher & 0b11111111111111111111111111111111;  //Fine
	uint64_t CipherTemp = cipher >> 32;
	uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine
	uint32_t temp = Left0;

	//Right0 = Right0 ^ Left0;
	temp = Right0 ^ roundKey;
	temp = f(temp);
	Left0 = Left0 ^ temp;
	Right0 = Right0 ^ Left0;

	//temp = Right0;
	//Right0 = Left0;
	//Left0 = temp;

	//printf("Cipher = %lx%lx\n", Left0, Right0);
	CipherTemp = (uint64_t)Left0 << 32;
	CipherTemp = CipherTemp + Right0;
	//printf("Cipher = %llx\n", CipherTemp);

	return CipherTemp;
}

extern void check_outputs(int keyNum, unsigned int keyUsed, uint32_t *keyAr);
//extern void final_check(unsigned int k0, unsigned int k1, unsigned int k2, unsigned int k3, unsigned int k4, unsigned int k5);

//K3 Finder using input differential 0x8080000080800000
void k3_finder() {
	uint64_t Plaintext0s[13];
	uint64_t Plaintext1s[13];
	uint64_t Ciphers0s[13];
	uint64_t Ciphers1s[13];

	Plaintext0s[0] = 0x1234567890ABCDEF; //A
	Plaintext0s[1] = 0x82954494abc2dfff; //B
	Plaintext0s[2] = 0x3a453465abc2da05; //C
	Plaintext0s[3] = 0x10D0FEB84DC4BB5D; //D
	Plaintext0s[4] = 0x4478168523DA0D8A; //E <- change

	Plaintext1s[0] = 0x92b45678102bcdef;
	Plaintext1s[1] = 0x21544942b42dfff;
	Plaintext1s[2] = 0xbac534652b42da05;
	Plaintext1s[3] = 0x9050feb8cd44bb5d;
	Plaintext1s[4] = 0xc4f81685a35a0d8a; //E <- change

	Ciphers0s[0] = 0xf43ae3eeb56e2bbf;
	Ciphers0s[1] = 0x36ed1f61106a1270;
	Ciphers0s[2] = 0x9dd74fdad0d61e07;
	Ciphers0s[3] = 0x7c06ccabe6b01946;
	Ciphers0s[4] = 0x712960a334b27730; //E <- change

	Ciphers1s[0] = 0x00ff73aaa933db7a;
	Ciphers1s[1] = 0x6d935a7ae39c77e8;
	Ciphers1s[2] = 0xfad6c0c60f4fb19b;
	Ciphers1s[3] = 0xcb0d4198e933750a;
	Ciphers1s[4] = 0x4faaf59792a90284; //E <- change

	for (int i = 0; i < 5; i++) {
		printf("Key3: Generating output%c.txt\n", 'A' + i);
		uint64_t Plaintext0 = Plaintext0s[i];
		uint64_t Plaintext1 = Plaintext1s[i];
		uint64_t Cipher0 = Ciphers0s[i];
		uint64_t Cipher1 = Ciphers1s[i];


		uint32_t Right0 = Cipher0 & 0b11111111111111111111111111111111;  //Fine
		uint64_t CipherTemp = Cipher0 >> 32;
		uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine

		uint32_t Right1 = Cipher1 & 0b11111111111111111111111111111111; //Fine
		CipherTemp = Cipher1 >> 32;
		uint32_t Left1 = CipherTemp & 0b11111111111111111111111111111111; //Fine

		uint32_t Y0 = Left0 ^ Right0; //Right input
		uint32_t Y1 = Left1 ^ Right1; //Right input

		uint32_t LeftPrime = Left0 ^ Left1; //Fine
		uint32_t ZPrime = LeftPrime ^ 0x02000000; //Fine

		//Set up for file///
		FILE* output;
		char fileName[] = "outputX.txt";
		fileName[6] = 'A' + i;
		output = fopen(fileName, "w");
		////////////////////

		uint32_t k = 0;
		uint32_t Z0 = 0;
		uint32_t Z1 = 0;
		uint32_t temp = 0;
		while (1 == 1) {
			temp = Y0 ^ k;
			Z0 = f(temp);

			temp = Y1 ^ k;
			Z1 = f(temp);

			temp = Z0 ^ Z1;

			if (temp == ZPrime) {
				//printf("Possible key found -> %lu\n", k);
				fprintf(output, "%lu\n", k);
			}

			if (k == 4294967295) { break; } //4294967295
			k++;
		}
		fclose(output);
	}
	check_outputs(3, 0, k3s);
}

//K2 Finder using input differential 0x0000000080800000
void k2_finder(unsigned int k3) {
	uint64_t Plaintext0s[13];
	uint64_t Plaintext1s[13];
	uint64_t Ciphers0s[13];
	uint64_t Ciphers1s[13];
	//decrypt1round(0000000, k3);
	Plaintext0s[0] = 0x1234567890ABCDEF; //A
	Plaintext0s[1] = 0x82954494abc2dfff; //B
	Plaintext0s[2] = 0x3a453465abc2da05; //C
	Plaintext0s[3] = 0x10D0FEB84DC4BB5D; //D
	Plaintext0s[4] = 0x4478168523DA0D8A; //E <- change
	
	//Diff 0x0000000080800000
	Plaintext1s[0] = 0x12345678102bcdef;
	Plaintext1s[1] = 0x829544942b42dfff;
	Plaintext1s[2] = 0x3a4534652b42da05;
	Plaintext1s[3] = 0x10d0feb8cd44bb5d;
	Plaintext1s[4] = 0x44781685a35a0d8a;

	// Diff of 0x0000000080800000
	//These need to have 1 round decrypted
	Ciphers0s[0] = decrypt1round(0xf43ae3eeb56e2bbf, k3); //0x74a3c67943b4279a;
	Ciphers0s[1] = decrypt1round(0x36ed1f61106a1270, k3); //0xcbaa3a420ba9e36d;
	Ciphers0s[2] = decrypt1round(0x9dd74fdad0d61e07, k3); //0x67a385a2f8bf1365;
	Ciphers0s[3] = decrypt1round(0x7c06ccabe6b01946, k3); //0xd4385514d091bbac;
	Ciphers0s[4] = decrypt1round(0x712960a334b27730, k3); //0xbbe62101b3781ed7; //E <- change

	//These need to have 1 round decrypted
	Ciphers1s[0] = decrypt1round(0x9f92f2c66edaa77e, k3); //0xc2e2bcb1d3b4c03e;
	Ciphers1s[1] = decrypt1round(0xdd14d3a4c69e6506, k3); //0xd26cb99ec4f840e3;
	Ciphers1s[2] = decrypt1round(0x240c87cb484d571a, k3); //0x080bfde1f618153e;
	Ciphers1s[3] = decrypt1round(0x89953438b5e26c39, k3); //0xce92023a6c78738e;
	Ciphers1s[4] = decrypt1round(0xf8d44cf0e6cde343, k3); //0x884e5eafb65d1089; //E <- change

	for (int i = 0; i < 5; i++) {
		printf("Key2: Generating output%c.txt\n", 'A' + i);
		uint64_t Plaintext0 = Plaintext0s[i];
		uint64_t Plaintext1 = Plaintext1s[i];
		uint64_t Cipher0 = Ciphers0s[i];
		uint64_t Cipher1 = Ciphers1s[i];


		uint32_t Right0 = Cipher0 & 0b11111111111111111111111111111111;  //Fine
		uint64_t CipherTemp = Cipher0 >> 32;
		uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine

		uint32_t Right1 = Cipher1 & 0b11111111111111111111111111111111; //Fine
		CipherTemp = Cipher1 >> 32;
		uint32_t Left1 = CipherTemp & 0b11111111111111111111111111111111; //Fine

		//uint32_t Y0 = Left0 ^ Right0; //Right input
		//uint32_t Y1 = Left1 ^ Right1; //Right input
		uint32_t Y0 = Right0; //Right input
		uint32_t Y1 = Right1; //Right input

		uint32_t LeftPrime = Left0 ^ Left1; //Fine
		//uint32_t ZPrime = LeftPrime ^ 0x02000000; //Fine
		uint32_t ZPrime = LeftPrime ^ 0x02000000; //Fine

		//Set up for file///
		FILE* output;
		char fileName[] = "outputX.txt";
		fileName[6] = 'A' + i;
		output = fopen(fileName, "w");
		////////////////////

		uint32_t k = 0;
		uint32_t Z0 = 0;
		uint32_t Z1 = 0;
		uint32_t temp = 0;

		while (1 == 1) {
			temp = Y0 ^ k;
			Z0 = f(temp);

			temp = Y1 ^ k;
			Z1 = f(temp);
			
			temp = Z0 ^ Z1;
			//printf("Checking key -> %lu\n", k);
			if (temp == ZPrime) {
				//printf("Possible key found -> %lu\n", k);
				fprintf(output, "%lu\n", k);
			}

			if (k == 4294967295) { break; } //4294967295
			k++;
		}
		fclose(output);
	}
	//fclose();
	check_outputs(2, k3, k2s);
}

void k1_finder(unsigned int k3, unsigned int k2) {
	uint64_t Plaintext0s[13];
	uint64_t Plaintext1s[13];
	uint64_t Ciphers0s[13];
	uint64_t Ciphers1s[13];
	//decrypt1round(0000000, k3);
	Plaintext0s[0] = 0x1234567890ABCDEF; //A
	Plaintext0s[1] = 0x82954494abc2dfff; //B
	Plaintext0s[2] = 0x3a453465abc2da05; //C
	Plaintext0s[3] = 0x10D0FEB84DC4BB5D; //D
	Plaintext0s[4] = 0x4478168523DA0D8A; //E <- change

	//Diff 0x0000000002000000
	Plaintext1s[0] = 0x1234567892abcdef;
	Plaintext1s[1] = 0x82954494a9c2dfff;
	Plaintext1s[2] = 0x3a453465a9c2da05;
	Plaintext1s[3] = 0x10d0feb84fc4bb5d;
	Plaintext1s[4] = 0x4478168521da0d8a;

	// Diff of 0x0000000002000000
	//These need to have 2 round decrypted
	Ciphers0s[0] = decrypt_other_rounds(decrypt1round(0xf43ae3eeb56e2bbf, k3), k2); //0x74a3c67943b4279a;
	Ciphers0s[1] = decrypt_other_rounds(decrypt1round(0x36ed1f61106a1270, k3), k2); //0xcbaa3a420ba9e36d;
	Ciphers0s[2] = decrypt_other_rounds(decrypt1round(0x9dd74fdad0d61e07, k3), k2); //0x67a385a2f8bf1365;
	Ciphers0s[3] = decrypt_other_rounds(decrypt1round(0x7c06ccabe6b01946, k3), k2); //0xd4385514d091bbac;
	Ciphers0s[4] = decrypt_other_rounds(decrypt1round(0x712960a334b27730, k3), k2); //0xbbe62101b3781ed7; //E <- change

	//These need to have 2 round decrypted
	Ciphers1s[0] = decrypt_other_rounds(decrypt1round(0x75e5401473ec369e, k3), k2); //0xf560f86d55865c3d;
	Ciphers1s[1] = decrypt_other_rounds(decrypt1round(0x30f587371f43a37c, k3), k2); //0xf4306cdb331742a0;
	Ciphers1s[2] = decrypt_other_rounds(decrypt1round(0x4e7a7b79d840d296, k3), k2); //0xee3f0c9c8b2e025e;
	Ciphers1s[3] = decrypt_other_rounds(decrypt1round(0x770c37c44d40ca49, k3), k2); //0xec0ef494f4c42d21;
	Ciphers1s[4] = decrypt_other_rounds(decrypt1round(0x9ec0ac4db0e7d888, k3), k2); //0xdfff4154221c4cd4; //E <- change

	for (int i = 0; i < 5; i++) {
		printf("Key1: Generating output%c.txt\n", 'A' + i);
		uint64_t Plaintext0 = Plaintext0s[i];
		uint64_t Plaintext1 = Plaintext1s[i];
		uint64_t Cipher0 = Ciphers0s[i];
		uint64_t Cipher1 = Ciphers1s[i];


		uint32_t Right0 = Cipher0 & 0b11111111111111111111111111111111;  //Fine
		uint64_t CipherTemp = Cipher0 >> 32;
		uint32_t Left0 = CipherTemp & 0b11111111111111111111111111111111;//Fine

		uint32_t Right1 = Cipher1 & 0b11111111111111111111111111111111; //Fine
		CipherTemp = Cipher1 >> 32;
		uint32_t Left1 = CipherTemp & 0b11111111111111111111111111111111; //Fine

		//uint32_t Y0 = Left0 ^ Right0; //Right input
		//uint32_t Y1 = Left1 ^ Right1; //Right input
		uint32_t Y0 = Right0; //Right input
		uint32_t Y1 = Right1; //Right input

		uint32_t LeftPrime = Left0 ^ Left1; //Fine
		//uint32_t ZPrime = LeftPrime ^ 0x02000000; //Fine
		uint32_t ZPrime = LeftPrime ^ 0x02000000; //Fine

		//Set up for file///
		FILE* output;
		char fileName[] = "outputX.txt";
		fileName[6] = 'A' + i;
		output = fopen(fileName, "w");
		////////////////////

		uint32_t k = 0;
		uint32_t Z0 = 0;
		uint32_t Z1 = 0;
		uint32_t temp = 0;

		while (1 == 1) {
			temp = Y0 ^ k;
			Z0 = f(temp);

			temp = Y1 ^ k;
			Z1 = f(temp);

			temp = Z0 ^ Z1;
			//printf("Checking key -> %lu\n", k);
			if (temp == ZPrime) {
				//printf("Possible key found -> %lu\n", k);
				fprintf(output, "%lu\n", k);
			}

			if (k == 4294967295) { break; } //4294967295
			k++;
		}
		fclose(output);
	}
	//fclose();
	check_outputs(1, k2, k1s);
}

void k0_finder(unsigned int k3, unsigned int k2, unsigned int k1) {
	printf("Key0, Key4, Key5: Generating\n");
	uint32_t k4 = 0;
	uint32_t k5 = 0;
	uint64_t Plaintext0s[13];
	uint64_t Plaintext1s[13];
	uint64_t Ciphers0s[13];
	uint64_t Ciphers1s[13];
	uint64_t Broken_Ciphers0s[13];
	uint64_t Broken_Ciphers1s[13];
	uint32_t possible_k4[13];
	uint32_t possible_k5[13];
	uint32_t possible_k4b[13];
	uint32_t possible_k5b[13];
	//decrypt1round(0000000, k3);
	Plaintext0s[0] = 0x1234567890ABCDEF; //A
	Plaintext0s[1] = 0x82954494abc2dfff; //B
	Plaintext0s[2] = 0x3a453465abc2da05; //C
	Plaintext0s[3] = 0x10D0FEB84DC4BB5D; //D
	Plaintext0s[4] = 0x4478168523DA0D8A; //E <- change

	//Diff 0x0000000002000000
	Plaintext1s[0] = 0x1234567892abcdef;
	Plaintext1s[1] = 0x82954494a9c2dfff;
	Plaintext1s[2] = 0x3a453465a9c2da05;
	Plaintext1s[3] = 0x10d0feb84fc4bb5d;
	Plaintext1s[4] = 0x4478168521da0d8a;

	// Diff of 0x0000000002000000
	//These need to have 3 round decrypted
	Ciphers0s[0] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0xf43ae3eeb56e2bbf, k3), k2), k1); //0x74a3c67943b4279a;
	Ciphers0s[1] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x36ed1f61106a1270, k3), k2), k1); //0xcbaa3a420ba9e36d;
	Ciphers0s[2] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x9dd74fdad0d61e07, k3), k2), k1); //0x67a385a2f8bf1365;
	Ciphers0s[3] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x7c06ccabe6b01946, k3), k2), k1); //0xd4385514d091bbac;
	Ciphers0s[4] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x712960a334b27730, k3), k2), k1); //0xbbe62101b3781ed7; //E <- change

	//These need to have 3 round decrypted
	Ciphers1s[0] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x75e5401473ec369e, k3), k2), k1); //0xf560f86d55865c3d;
	Ciphers1s[1] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x30f587371f43a37c, k3), k2), k1); //0xf4306cdb331742a0;
	Ciphers1s[2] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x4e7a7b79d840d296, k3), k2), k1); //0xee3f0c9c8b2e025e;
	Ciphers1s[3] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x770c37c44d40ca49, k3), k2), k1); //0xec0ef494f4c42d21;
	Ciphers1s[4] = decrypt_other_rounds(decrypt_other_rounds(decrypt1round(0x9ec0ac4db0e7d888, k3), k2), k1); //0xdfff4154221c4cd4; //E <- change

	uint32_t Plaintext0s_lefts[13];
	uint32_t Plaintext0s_rights[13];
	uint32_t Plaintext1s_lefts[13];
	uint32_t Plaintext1s_rights[13];

	uint32_t Ciphers0s_lefts[13];
	uint32_t Ciphers0s_rights[13];
	uint32_t Ciphers1s_lefts[13];
	uint32_t Ciphers1s_rights[13];

	uint32_t C_Right0 = 0;
	uint32_t C_Left0 = 0;
	uint32_t P_Right0 = 0;
	uint32_t P_Left0 = 0;
	uint32_t C_Right1 = 0;
	uint32_t C_Left1 = 0;
	uint32_t P_Right1 = 0;
	uint32_t P_Left1 = 0;
	uint64_t temp = 0;

	//Set up for file///
	FILE* keyFile;
	char fileName[] = "key0.txt";
	keyFile = fopen(fileName, "a");
	////////////////////
	//Set up for file///
	FILE* keyFile2;
	keyFile2 = fopen("key4.txt", "a");
	////////////////////
	//Set up for file///
	FILE* keyFile3;
	keyFile3 = fopen("key5.txt", "a");
	////////////////////
 
	//Guess k0
	uint32_t k = 0;
	int count = 0;
	while (1 == 1) {
		
		//Almost broken ciphers
		Broken_Ciphers0s[0] = decrypt_last_round(Ciphers0s[0], k); //0x74a3c67943b4279a;
		Broken_Ciphers0s[1] = decrypt_last_round(Ciphers0s[1], k); //0xcbaa3a420ba9e36d;
		Broken_Ciphers0s[2] = decrypt_last_round(Ciphers0s[2], k); //0x67a385a2f8bf1365;
		Broken_Ciphers0s[3] = decrypt_last_round(Ciphers0s[3], k); //0xd4385514d091bbac;
		Broken_Ciphers0s[4] = decrypt_last_round(Ciphers0s[4], k); //0xbbe62101b3781ed7; //E <- change

		//Almost broken ciphers
		Broken_Ciphers1s[0] = decrypt_last_round(Ciphers1s[0], k); //0xf560f86d55865c3d;
		Broken_Ciphers1s[1] = decrypt_last_round(Ciphers1s[1], k); //0xf4306cdb331742a0;
		Broken_Ciphers1s[2] = decrypt_last_round(Ciphers1s[2], k); //0xee3f0c9c8b2e025e;
		Broken_Ciphers1s[3] = decrypt_last_round(Ciphers1s[3], k); //0xec0ef494f4c42d21;
		Broken_Ciphers1s[4] = decrypt_last_round(Ciphers1s[4], k); //0xdfff4154221c4cd4; //E <- change
		
		for (int i = 0; i < 5; i++) {
			//Set up left/right cipher texts
			C_Right0 = Broken_Ciphers0s[i] & 0b11111111111111111111111111111111;  //Fine
			temp = Broken_Ciphers0s[i] >> 32;
			C_Left0 = temp & 0b11111111111111111111111111111111;//Fine

			C_Right1 = Broken_Ciphers1s[i] & 0b11111111111111111111111111111111; //Fine
			temp = Broken_Ciphers1s[i] >> 32;
			C_Left1 = temp & 0b11111111111111111111111111111111; //Fine

			//Set up left/right plan texts
			P_Right0 = Plaintext0s[i] & 0b11111111111111111111111111111111;  //Fine
			temp = Plaintext0s[i] >> 32;
			P_Left0 = temp & 0b11111111111111111111111111111111;//Fine

			P_Right1 = Plaintext1s[i] & 0b11111111111111111111111111111111; //Fine
			temp = Plaintext1s[i] >> 32;
			P_Left1 = temp & 0b11111111111111111111111111111111; //Fine

			//Populate lists with K4s and K5s
			possible_k4[i] = P_Left0 ^ C_Left0;
			possible_k4b[i] = P_Left1 ^ C_Left1;
			possible_k5[i] = P_Right0 ^ C_Right0;
			possible_k5b[i] = P_Right1 ^ C_Right1;
		}

		//Check to see if all K4s match each other & all K5s match each other
		for (int i = 0; i < 5; i++) {
			if ((possible_k4[0] != possible_k4[i]) || (possible_k4[0] != possible_k4b[i]) || (possible_k5[0] != possible_k5[i]) || (possible_k5[0] != possible_k5b[i])) {
				//Keys don't match -> K0 is not valid -> break
				break;
			}
			else if (i == 4) {
				//Loop end reached with no breaks -> possible k0 and certain k4, k5
				//printf("k0 = %lu\n", k);
				k0s[count][0] = k;
				k0s[count][1] = k3;
				k0s[count][2] = k2;
				k0s[count][3] = k1;
				fprintf(keyFile, "%lu\n", k);
				//printf("k4 = %lu\n", possible_k4[0]);
				k4s[count][0] = possible_k4[0];
				k4s[count][1] = k3;
				k4s[count][2] = k2;
				k4s[count][3] = k1;
				fprintf(keyFile2, "%lu\n", possible_k4[0]);
				//k4 = possible_k4[0];
				//printf("k5 = %lu\n", possible_k5[0]);
				k5s[count][0] = possible_k5[0];
				k5s[count][1] = k3;
				k5s[count][2] = k2;
				k5s[count][3] = k1;
				fprintf(keyFile3, "%lu\n", possible_k5[0]);
				//k5 = possible_k5[0];
				count++;
			}
		}

		if (k == 4294967295) { break; } //4294967295
		k++;
	}
	fclose(keyFile);
	fclose(keyFile2);
	fclose(keyFile3);
}

int main()
{
	
	//init arrays
	for (int i = 0; i < 10000; i++) {
		k3s[i][0] = 0;
		k2s[i][0] = 0;
		k1s[i][0] = 0;
		k0s[i][0] = 0;
		k4s[i][0] = 0;
		k5s[i][0] = 0;
	}

	//Key 3 finder
	k3_finder(k3s);


	//Key 2 finder loop
	for (int i = 0; i < 4; i++) {
		k2_finder(k3s[i][0]);
	}
	
	
	//Key 1 finder loop
	for (int i = 0; i < 10000; i++) {
		if (k2s[i][0] == 0) {
			break;
		}
		for (int j = 0; j < 4; j++) {
			if (k3s[j][0] == k2s[i][1]) {
				printf("run %d\n",i);
				k1_finder(k3s[j][0], k2s[i][0]);
			}
			else {
				printf("Skipped\n");
			}
		}
	}



	//Key 0, 4, 5 finder
	for (int i = 0; i < 10000; i++) {
		if (k2s[i][0] == 0) {
			break;
		}
		for (int j = 0; j < 10000; j++) {
			for (int p = 0; p < 5; p++) {
				if (k3s[p][0] == k2s[i][1] && k2s[j][0] == k1s[i][2]) {
					printf("run %d\n", i);
					k0_finder(k3s[p][0], k2s[j][0], k1s[i][0]);
				}
				else {
					//printf("Skipped\n");
				}
			}
		}
	}



	//Key 3 print loop
	for (int i = 0; i < 4; i++) {
		printf("Key3 option %d = %u\n", i, k3s[i][0]);
	}printf("\n");

	//Key 2 print loop
	for (int i = 0; i < 10000; i++) {
		if (k2s[i][0] == 0) {
			break;
		}
		printf("Key2(%u) option %d = %u\n", k2s[i][1], i, k2s[i][0]);
	}printf("\n");

	//Key 1 print loop
	for (int i = 0; i < 10000; i++) {
		if (k1s[i][0] == 0) {
			break;
		}
		printf("Key1(?, %u) option %d = %u\n", k1s[i][2], i, k1s[i][0]);
	}printf("\n");

	//Key 0, 5, 6 print loop
	for (int i = 0; i < 10000; i++) {
		if (k0s[i][0] == 0) {
			break;
		}
		printf("Key0(%u, %u, %u) option %d = %u\n", k0s[i][1], k0s[i][2], k0s[i][2], i, k0s[i][0]);
		printf("Key4(%u, %u, %u) option %d = %u\n", k4s[i][1], k4s[i][2], k4s[i][2], i, k4s[i][0]);
		printf("Key5(%u, %u, %u) option %d = %u\n", k5s[i][1], k5s[i][2], k5s[i][2], i, k5s[i][0]);
	}printf("\n");

    return 1;
}