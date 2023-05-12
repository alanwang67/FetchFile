#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

// https://stackoverflow.com/questions/55579144/how-to-fix-makefile-to-properly-include-lcrypto-to-avoid-linker-error-undefine

#pragma pack(push,1)
typedef struct BootEntry {
    unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
    unsigned char  BS_OEMName[8];     // OEM Name in ASCII
    unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
    unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
    unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
    unsigned char  BPB_NumFATs;       // Number of FATs
    unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
    unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
    unsigned char  BPB_Media;         // Media type
    unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
    unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
    unsigned short BPB_NumHeads;      // Number of heads in storage device
    unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
    unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
    unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
    unsigned short BPB_ExtFlags;      // A flag for FAT
    unsigned short BPB_FSVer;         // The major and minor version number
    unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
    unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
    unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
    unsigned char  BPB_Reserved[12];  // Reserved
    unsigned char  BS_DrvNum;         // BIOS INT13h drive number
    unsigned char  BS_Reserved1;      // Not used
    unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
    unsigned int   BS_VolID;          // Volume serial number
    unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
    unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
    unsigned char  DIR_Name[11];      // File name
    unsigned char  DIR_Attr;          // File attributes
    unsigned char  DIR_NTRes;         // Reserved
    unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
    unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
    unsigned short DIR_CrtDate;       // Created day
    unsigned short DIR_LstAccDate;    // Accessed day
    unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
    unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
    unsigned short DIR_WrtDate;       // Written day
    unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
    unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

void printDirectoryEntry(DirEntry* directoryEntry) {
    int i = 0;
    while (i < 11) {
        if (i == 8 && directoryEntry->DIR_Name[i] != ' ') {
            printf("%c",'.');
        }
        if (directoryEntry->DIR_Name[i] != ' ') {
            printf("%c", directoryEntry->DIR_Name[i]);
        }
        i += 1;
    }
    if (directoryEntry->DIR_Attr == 0x10) {
        printf("%c", '/');
    }
    printf("%s%d%s%d%s\n", " (size = ", directoryEntry->DIR_FileSize, ", starting cluster = ", (directoryEntry->DIR_FstClusHI) >> 2 | (directoryEntry->DIR_FstClusLO), ")");
}

// compares directoryFileName and fileName to see if
// only accepts files
int isSameFile(char* fileName, char* directoryFileName) {
    fileName += 1;
    directoryFileName += 1;
    int i = 0;
    char compareFileName[12];
    int index = 0;

    // we have to adjust because we skipped the first character
    while (i < 10) {
        if ((i == 7) && (*directoryFileName != ' '))  {
            compareFileName[index] = '.';
            index += 1;
        }
        if (*directoryFileName != ' ') {
            compareFileName[index] = *directoryFileName;
            index += 1;
        }
        directoryFileName += 1;
        i += 1;
    }

    compareFileName[index] = '\0';

    return (strcmp(fileName, compareFileName) == 0);
}

int compareHash(char* hash, char* fileHash) {
    unsigned char* hexDigitOfHash = malloc(9);
    int i = 0;
    while (i < 20) {
        sprintf(hexDigitOfHash, "%08x", *fileHash);
        if ((*(hash + i*2) != hexDigitOfHash[6]) || (*(hash + (i*2) + 1) != hexDigitOfHash[7])) {
            return 0;
        }
        fileHash += 1;
        i += 1;
    }
    return 1;
}

int main(int argc, char *argv[]) {

    // when no option arguments are provided
    if (argc <= 2) {
        printf("%s\n", "Usage: ./nyufile disk <options>");
        printf("%s\n", "  -i                     Print the file system information.");
        printf("%s\n", "  -l                     List the root directory.");
        printf("%s\n", "  -r filename [-s sha1]  Recover a contiguous file.");
        printf("%s\n", "  -R filename -s sha1    Recover a possibly non-contiguous file.");
        return 0;
    }

    int opt;
    struct stat sb;
    int fd = open(argv[1], O_RDWR);
    fstat(fd, &sb);
    char* disk = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

    BootEntry* bootSector = (BootEntry*) disk;
    int sizeOfCluster = bootSector->BPB_SecPerClus * bootSector->BPB_BytsPerSec;
    unsigned int startFAT = bootSector->BPB_BytsPerSec * bootSector->BPB_RsvdSecCnt;
    unsigned int endFAT = startFAT + (bootSector->BPB_NumFATs * bootSector->BPB_FATSz32 * bootSector->BPB_BytsPerSec);
    unsigned int* FAT = (unsigned int *) (disk+startFAT);
    char* dataArea = disk + endFAT;

    char arguments[2];
    char* fileName;
    char* hash;

    while ((opt = getopt(argc, argv, "ilr:R:s:")) != -1) {
        switch (opt) {
            case 'i':
            {
                printf("%s%d\n", "Number of FATs = ", bootSector->BPB_NumFATs);
                printf("%s%hu\n", "Number of bytes per sector = ", bootSector->BPB_BytsPerSec);
                printf("%s%d\n", "Number of sectors per cluster = ", bootSector->BPB_SecPerClus);
                printf("%s%hu\n", "Number of reserved sectors = ", bootSector->BPB_RsvdSecCnt);
                break;
            }
            case 'l':
            {
                unsigned int clusterIndex = bootSector->BPB_RootClus;
                DirEntry* directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
                int byteOfCluster;
                int numberOfEntries = 0;
                // iterate over directory if it spans multiple clusters
                while (1) {
                    byteOfCluster = 0;
                    // iterate over each directoryEntry in a cluster
                    while (directoryEntry->DIR_Name[0] != 0x00 && byteOfCluster < sizeOfCluster) {
                        if ((directoryEntry->DIR_Name[0]) != 0xE5) {
                            printDirectoryEntry(directoryEntry);
                            numberOfEntries += 1;
                        }
                        // go to the entry in the directory
                        byteOfCluster += 32;
                        directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster) + byteOfCluster);
                    }

                    if (FAT[clusterIndex] >= 0x0ffffff8) {
                        break;
                    }

                    // navigate to the start of the next cluster
                    clusterIndex = FAT[clusterIndex];
                    directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
                }
                printf("%s%d\n", "Total number of entries = ", numberOfEntries);
                break;
            }
            case 'r':
            {
                arguments[0] = 'r';
                fileName = optarg;
                break;
            }
            case 'R':
            {
                printf("%s%s\n", optarg, ": file not found");
                break;
            }
            case 's':
            {
                arguments[1] = 's';
                hash = optarg;
                break;
            }
            default:
            {
                printf("%s\n", "Usage: ./nyufile disk <options>");
                printf("%s\n", "  -i                     Print the file system information.");
                printf("%s\n", "  -l                     List the root directory.");
                printf("%s\n", "  -r filename [-s sha1]  Recover a contiguous file.");
                printf("%s\n", "  -R filename -s sha1    Recover a possibly non-contiguous file.");
            }
        }
    }

    if (arguments[0] == 'r') {
        unsigned int clusterIndex = bootSector->BPB_RootClus;
        DirEntry* directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
        unsigned int fileSize;
        int byteOfCluster;

        if (arguments[1] == 's') {
            while (1) {
            byteOfCluster = 0;
            while (directoryEntry->DIR_Name[0] != 0x00 && byteOfCluster < sizeOfCluster) {
                if ((directoryEntry->DIR_Name[0] == 0xE5) && isSameFile(fileName, directoryEntry->DIR_Name)) {
                    fileSize = directoryEntry->DIR_FileSize;
                    int i = sizeOfCluster;
                    int fileClusterIndex = (directoryEntry->DIR_FstClusHI) >> 2 | (directoryEntry->DIR_FstClusLO);
                    unsigned char* outputHash = malloc(10);

                    SHA1(dataArea + ((fileClusterIndex-2)*sizeOfCluster), fileSize, outputHash);

                    if (compareHash(hash, outputHash)) {
                        while (i < fileSize) {
                            FAT[fileClusterIndex] = fileClusterIndex + 1;
                            fileClusterIndex += 1;
                            i += sizeOfCluster;
                        }

                        FAT[fileClusterIndex] = 0x0ffffff8;
                        directoryEntry->DIR_Name[0] = fileName[0];
                        printf("%s%s\n", fileName, ": successfully recovered with SHA-1");
                        return 0;
                    }
                }
                byteOfCluster += 32;
                directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster) + byteOfCluster);
            }

            if (FAT[clusterIndex] >= 0x0ffffff8) {
                break;
            }

            // navigate to the start of the next cluster
            clusterIndex = FAT[clusterIndex];
            directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
            }
            printf("%s%s\n", fileName, ": file not found");

            return 0;
        }

        int ambiguousFiles = 0;

        // determines if there are ambiguous files
        while (1) {
            byteOfCluster = 0;
            while (directoryEntry->DIR_Name[0] != 0x00 && byteOfCluster < sizeOfCluster) {
                if ((directoryEntry->DIR_Name[0] == 0xE5) && isSameFile(fileName, directoryEntry->DIR_Name)) {
                    ambiguousFiles += 1;
                }
                byteOfCluster += 32;
                directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster) + byteOfCluster);
            }

            if (FAT[clusterIndex] >= 0x0ffffff8) {
                break;
            }

            // navigate to the start of the next cluster
            clusterIndex = FAT[clusterIndex];
            directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
        }

        if (ambiguousFiles > 1) {
            printf("%s%s\n", fileName, ": multiple candidates found");
            return 0;
        }

        clusterIndex = bootSector->BPB_RootClus;
        directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
        // iterate over directory if it spans multiple clusters
        while (1) {
            byteOfCluster = 0;
            while (directoryEntry->DIR_Name[0] != 0x00 && byteOfCluster < sizeOfCluster) {
                if ((directoryEntry->DIR_Name[0] == 0xE5) && isSameFile(fileName, directoryEntry->DIR_Name)) {

                    directoryEntry->DIR_Name[0] = fileName[0];
                    fileSize = directoryEntry->DIR_FileSize;
                    int i = sizeOfCluster;
                    int fileClusterIndex = (directoryEntry->DIR_FstClusHI) >> 2 | (directoryEntry->DIR_FstClusLO);

                    while (i < fileSize) {
                        FAT[fileClusterIndex] = fileClusterIndex + 1;
                        fileClusterIndex += 1;
                        i += sizeOfCluster;
                    }

                    FAT[fileClusterIndex] = 0x0ffffff8;
                    printf("%s%s\n", fileName, ": successfully recovered");
                    return 0;
                }
                byteOfCluster += 32;
                directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster) + byteOfCluster);
            }

            if (FAT[clusterIndex] >= 0x0ffffff8) {
                break;
            }

            // navigate to the start of the next cluster
            clusterIndex = FAT[clusterIndex];
            directoryEntry = (DirEntry*) (dataArea + ((clusterIndex-2)*sizeOfCluster));
        }
        printf("%s%s\n", fileName, ": file not found");
    }

    return 0;
}
