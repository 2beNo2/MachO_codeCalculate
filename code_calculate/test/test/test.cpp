// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <stdio.h>
#include <LIEF/LIEF.hpp>
#include "md5.h"
#include "xxhash.h"

using namespace std;

#define FAT_MAGIC         0xcafebabe
#define FAT_CIGAM         0xbebafeca  /* NXSwapLong(FAT_MAGIC) */
#define FAT_MAGIC_64    0xcafebabf
#define FAT_CIGAM_64    0xbfbafeca  /* NXSwapLong(FAT_MAGIC_64) */
#define MH_MAGIC         0xfeedface  /* the mach magic number */
#define MH_CIGAM         0xcefaedfe  /* NXSwapInt(MH_MAGIC) */
#define MH_MAGIC_64    0xfeedfacf   /* the 64-bit mach magic number */
#define MH_CIGAM_64    0xcffaedfe   /* NXSwapInt(MH_MAGIC_64) */


#define IS_FAT(x) ((x) == FAT_MAGIC || (x) == FAT_CIGAM)
#define IS_THIN(x) ((x) == MH_MAGIC || (x) == MH_CIGAM || (x) == MH_MAGIC_64 || (x) == MH_CIGAM_64)
#define IS_MAGIC(x) (IS_FAT(x) || IS_THIN(x))


size_t fpeek(void* ptr, size_t size, size_t nitems, FILE* stream) {
	size_t result = fread(ptr, size, nitems, stream);
	fseek(stream, -(result * size), SEEK_CUR);
	return result;
}

#define PEEK(x, f)  fpeek(&x, sizeof(x), 1, f)
#define READ(x, f)  fread(&x, sizeof(x), 1, f)


void getCodeInfo(LIEF::MachO::it_sections section, uint32_t*code_offset, uint32_t* code_size, const char * str) {
	for (auto sec = section.begin(); sec != section.end(); sec++) {
		auto secTmp = *sec;
		if (strcmp(secTmp.name().c_str(), str) == 0) {
			*code_offset = secTmp.offset();
			*code_size = secTmp.size();
		}
	}
}


bool getSectionInfo(LIEF::MachO::Binary* binary, uint32_t* code_offset, uint32_t* code_size, const char* str) {
	//获取代码段的结构体
	LIEF::MachO::SegmentCommand* segmentCommand = binary->get_segment("__TEXT");
	//cout << *segmentCommand << endl;

	//获取节
	LIEF::MachO::it_sections sections = segmentCommand->sections();

	//获取code的信息		
	if (segmentCommand->has_section(str)) {
		getCodeInfo(sections, code_offset, code_size, str);
		return true;
	}
	return false;
}


void getCodeBuff(char* dataBuff, uint32_t code_offset, uint32_t code_size, uint32_t fat_offset, FILE* fp) {
	if (dataBuff == NULL) {
		cout << "malloc error" << endl;
		return;
	}
	fseek(fp, code_offset + fat_offset, SEEK_SET);
	fread(dataBuff, 1, code_size, fp);
}


void getCodeMd5(char* dataBuff, uint32_t code_size) {
	MD5_CTX mdContext;
	MD5Init(&mdContext);
	MD5Update(&mdContext, (const unsigned char*)dataBuff, code_size);
	unsigned char digest[16] = { 0 };
	MD5Final(digest, &mdContext);
	cout << "md5: ";
	for (int i = 0; i < 16; ++i) {
		printf("%02x", digest[i]);
	}
}


void getCode64XXHash(char* dataBuff, uint32_t code_size) {
	unsigned int seed = 5371;
	unsigned long long ullTextHash = 0;
	ullTextHash = XXH64(dataBuff, code_size, seed);

	cout << "  xxhash: " << std::hex << ullTextHash << endl;
}


void getCode32XXHash(char* dataBuff, uint32_t code_size) {
	unsigned int seed = 5371;
	unsigned long long ullTextHash = 0;
	ullTextHash = XXH32(dataBuff, code_size, seed);

	cout << "  xxhash: " << std::hex << ullTextHash << endl;
}


void calculateFat(const char* filePath, FILE* fp) {
	//先获取Fat头Binary
	std::unique_ptr<LIEF::MachO::FatBinary> machO_binary = LIEF::MachO::Parser::parse(filePath, LIEF::MachO::ParserConfig::quick());

	//获取MachO头Binary
	LIEF::MachO::Binary* tmpBinary = machO_binary->pop_back();
	
	while (tmpBinary) {
		//获取MachO头结构体
		LIEF::MachO::Header header = tmpBinary->header();

		//FAT格式中的代码偏移，需要加上MachO头的偏移(Fat_Arch->file_offset)
		uint32_t fat_offset = tmpBinary->fat_offset();
		uint32_t code_offset = 0;
		uint32_t code_size = 0;
		char* dataBuff = NULL;

		if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM64) {
			cout << "arm64：" << endl;
		}else if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM) {
			cout << "arm：" << endl;
		}

		if (getSectionInfo(tmpBinary, &code_offset, &code_size, "il2cpp")) {
			cout << "il2cpp ==>";
			dataBuff = (char*)malloc(code_size);

			getCodeBuff(dataBuff, code_offset, code_size, fat_offset, fp);
			getCodeMd5(dataBuff, code_size);

			if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM64) {
				getCode64XXHash(dataBuff, code_size);
			}
			else if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM) {
				getCode32XXHash(dataBuff, code_size);
			}
			
		}
		
		if (getSectionInfo(tmpBinary, &code_offset, &code_size, "__text")) {
			cout << "__text ==>";
			dataBuff = (char*)malloc(code_size);

			getCodeBuff(dataBuff, code_offset, code_size, fat_offset, fp);
			getCodeMd5(dataBuff, code_size);
			
			if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM64) {
				getCode64XXHash(dataBuff, code_size);
			}
			else if (header.cpu_type() == LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM) {
				getCode32XXHash(dataBuff, code_size);
			}

		}
		free(dataBuff);

		tmpBinary = machO_binary->pop_back();
	}
}


int main(int argc, char** argv){

    if (argc < 2) {
        cout << "Non-exist file path" << endl;
        return 0;
    }

	FILE* file = fopen(argv[1], "rb+");
	//FILE* file = fopen("C:\\Users\\e\\Desktop\\新建文件夹\\freefiremax", "rb+");
	if (!file) {
		cout << "Couldn't open file!" << endl;
		return 0;
	}

	uint32_t magic;
	PEEK(magic, file);

	if (!IS_MAGIC(magic)) {
		std::ostringstream o;
		o << "Unknown magic: 0x" << std::hex << magic;
		cout <<  o.str() << endl;
		fclose(file);
		return 0;
	}
	
	calculateFat(argv[1], file);

	fclose(file);
    return 0;
}

