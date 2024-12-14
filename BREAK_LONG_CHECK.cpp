#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <iomanip>
#include <vector>

using namespace std;

extern "C" void check_outputs(int keyNum, unsigned int keyUsed, uint32_t(*keyAr)[4]) {
	//cout << "Running C++!\n";
	unordered_map<string,int> multi_match;

	for (int i = 0; i < 5; i++) {
		//Check output.txt
		string fileName = "outputX.txt";
		fileName[6] = 'A' + i;
		ifstream file(fileName);
		string possibleKey;
		cout << "Checking " << fileName << "\n";
		if (file.is_open()) {
			while (getline(file, possibleKey)) {

				if (multi_match.contains(possibleKey)) {
					multi_match[possibleKey]++;
				}
				else {
					multi_match[possibleKey] = 1;
				}
			}
		}
		file.close();
	}

	//Set up for file///
	FILE* keyFile;
	char fileName[] = "keyX.txt";
	fileName[3] = '0' + keyNum;
	keyFile = fopen(fileName, "a");
	////////////////////

	int count = 0;
	while (keyAr[count][0] != 0) {
		count++;
	}
	//fprintf(keyFile, "x%u\n", keyUsed);
	for (auto i = multi_match.begin(); i != multi_match.end(); i++) {
		if (i->second >= 5) {
			//cout << i->first << " " << i->second << "\n";
			long long convert = stoll(i->first);
			unsigned int possibleKey32 = convert;
			//printf("%lx\n", possibleKey32);
			//safeSafeCount++;
			//Write to key[keyNum].txt
			fprintf(keyFile, "%lu\n", possibleKey32);
			
			
			if (keyNum == 3) {
				keyAr[count][0] = possibleKey32;
			}
			else if (keyNum == 2) {
				keyAr[count][0] = possibleKey32;
				keyAr[count][1] = keyUsed;
			}
			else if (keyNum == 1) {
				keyAr[count][0] = possibleKey32;
				keyAr[count][1] = 0;//How will i get Key3 here
				keyAr[count][2] = keyUsed; //Key2
			}

			count++;
		}
	}
	printf("\n");
	fclose(keyFile);
}