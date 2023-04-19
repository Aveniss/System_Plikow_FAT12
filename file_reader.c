
//
// Created by kamil on 04.01.2023.
//

#include "file_reader.h"
#include <stddef.h>
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"

uint16_t funkcjPomocnicza(uint16_t one,uint16_t two)
{
    uint16_t three = 0;
    int licznik = 0;
    for (int i = 0; i < 8; ++i) {
        if ((one >> i) & 1)
            three += (uint16_t) pow(2, i);
        licznik++;
    }
    for (int i = 0; i < 4; ++i) {
        if ((two >> i) & 1) {
            three += pow(2, licznik);
        }
        licznik++;
    }
    return three;
}

struct clusters_chain_t *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster) {
    if (buffer == NULL || size == 0 || first_cluster == 0)
        return NULL;
    uint16_t cluster = first_cluster, one, two, three;
    int numberOfClusters = 0;

    uint8_t *tab = (uint8_t *) buffer;

    while (cluster != 0 && cluster < size) {
        three = 0;
        one = *(tab + (int) (cluster * 1.5));
        two = *(tab + (int) (cluster * 1.5) + 1);

        if (cluster % 2 == 0) {
            three = funkcjPomocnicza(one,two);
        } else {
            three = (one | (two << 8)) >> 4;
        }
        if(!(three >= 0x0002 && three <= 0xFFF6))
            break;
        numberOfClusters++;
        if (three >= size || cluster >= 3071||cluster >= 4090)
            break;
        cluster = three;

    }

    struct clusters_chain_t *chain = calloc(1, sizeof(struct clusters_chain_t));
    if (chain == NULL)
        return NULL;
    chain->size = numberOfClusters;
    chain->clusters = calloc(numberOfClusters, sizeof(size_t));
    if (chain->clusters == NULL)
        return NULL;
    numberOfClusters = 0;
    cluster = first_cluster;

    while (cluster != 0 && cluster < size) {
        three = 0;
        *(chain->clusters + numberOfClusters) = cluster;
        one = *(tab + (int) (cluster * 1.5));
        two = *(tab + (int) (cluster * 1.5) + 1);


        if (cluster % 2 == 0){
            three = funkcjPomocnicza(one,two);
        } else {
            three = (one | (two << 8)) >> 4;
        }
        if(!(three >= 0x0002 && three <= 0xFFF6))
            break;
        numberOfClusters++;
        if (three >= size || cluster >= 3071 || cluster >= 4090)
            break;
        cluster = three;

    }

    return chain;
}



struct disk_t* disk_open_from_file(const char* volume_file_name)
{
    if(volume_file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }
    FILE *file= fopen(volume_file_name,"rb");
    if (file == NULL) { // or NULL if tested function returns a pointer
        errno = ENOENT;
        return NULL; // Things just went south.
    }
    struct disk_t *disk = calloc(1,sizeof(struct disk_t));
    if(disk == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    disk->file = file;
    return disk;
}
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    if(pdisk == NULL || buffer == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    fseek(pdisk->file, first_sector * BYTES_PER_SECTOR, SEEK_SET);
    int read_block = fread(buffer, BYTES_PER_SECTOR, sectors_to_read, pdisk->file);
    if(read_block < 0)
    {
        errno = ERANGE;
        return -1;
    }
    return read_block;
}
int disk_close(struct disk_t* pdisk)
{
    if(pdisk != NULL)
    {
        if(pdisk->file!=NULL)
            fclose(pdisk->file);
        free(pdisk);
        return 0;
    }
    errno = EFAULT;
    return -1;
}
struct file_t* file_open(struct volume_t* pvolume, const char* file_name)
{
    if(pvolume == NULL || file_name == NULL)
    {
        errno = EFAULT;
        return NULL;
    }
    char* sectors = calloc(pvolume->sectors_per_rootdir,BYTES_PER_SECTOR);
    if(sectors == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    lba_t numberOfFatEntry = 0;
    struct fat_entry_t *entryFat;
    int notExist = 1;
    char name[14]={0};
    int res = disk_read(pvolume->disk, pvolume->fat2_position + pvolume->superSector->sectors_per_fat, sectors, pvolume->sectors_per_rootdir);
    if (res != (int)pvolume->sectors_per_rootdir) {
        errno = ENOENT;
        return NULL;
    }
    while (numberOfFatEntry*30 < pvolume->sectors_per_rootdir*BYTES_PER_SECTOR)
    {
        memset(name,'\0',14);
        int d = 0;
        for (int i = 0; i < 11; ++i) {
            if(*(sectors + numberOfFatEntry * 32 + i) == '\0')
                break;
            if(*(sectors + numberOfFatEntry * 32 + i) != ' ' && (*(sectors + numberOfFatEntry * 32 + i) >= 'A' && *(sectors + numberOfFatEntry * 32 + i) <= 'Z' || *(sectors + numberOfFatEntry * 32 + i) == '_')) {
                *(name + d) = *(sectors + numberOfFatEntry * 32 + i);
                d++;
            }
        }
        int size = strlen(name);
        if((*(name+size-3)=='T'&&*(name+size-2)=='X'&&*(name+size-1)=='T')||(*(name+size-3)=='B'&&*(name+size-2)=='I'&&*(name+size-1)=='N'))
        {
            for (int i = 0; i < 3; ++i) {
                *(name+size-i) = *(name+size-i-1);
            }
            *(name+size-3)='.';
        }
        else if(*(name+size-2)=='T'&&*(name+size-1)=='X')
        {
            for (int i = 0; i < 2; ++i) {
                *(name+size-i) = *(name+size-i-1);
            }
            *(name+size-2)='.';
        }

        if(strcmp(file_name,name)==0)
        {
            notExist =0;
            break;
        }
        numberOfFatEntry++;
    }

    if(notExist)
    {
        errno = ENOENT;
        free(sectors);
        return NULL;
    }
    entryFat = (struct fat_entry_t*)(sectors + numberOfFatEntry * 32);
    if(entryFat->file_size == 0)
    {
        errno = EISDIR;
        free(sectors);
        return NULL;
    }

    struct file_t *file  = calloc(1,sizeof(struct file_t));
    if(file == NULL)
    {
        errno = ENOMEM;
        free(sectors);
        return NULL;
    }
    file->fileSize = entryFat->file_size;
    file->volume = pvolume;
    uint8_t *fatTab = (uint8_t *) malloc(pvolume->superSector->bytes_per_sector * pvolume->superSector->sectors_per_fat);
    disk_read(pvolume->disk, pvolume->fat1_position,fatTab, pvolume->superSector->sectors_per_fat);
    file->chain = get_chain_fat12(fatTab,pvolume->superSector->sectors_per_fat*pvolume->superSector->bytes_per_sector,entryFat->low_cluster_index);
    free(sectors);
    free(fatTab);
    file->position = 0;
    return file;
}
int file_close(struct file_t* stream)
{
    if (stream != NULL) {
        free(stream->chain->clusters);
        free(stream->chain);
        free(stream);
        return 0;
    }
    errno = EFAULT;
    return -1;
}
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream)
{
    if (ptr == NULL || size == 0 || nmemb == 0 || stream == NULL) {
        errno = EFAULT;
        return -1;
    }
    int numberOfBlocks = 0;
    int currentCluster = stream->position/(stream->volume->superSector->sectors_per_cluster*BYTES_PER_SECTOR);
    char* cluster = (char *) calloc(stream->volume->superSector->sectors_per_cluster * stream->volume->superSector->bytes_per_sector, sizeof(char));
    if(cluster == NULL)
        return -1;
    disk_read(stream->volume->disk, stream->volume->cluster2_position + (stream->chain->clusters[currentCluster] - 2) * stream->volume->superSector->sectors_per_cluster, cluster, stream->volume->superSector->sectors_per_cluster);
    for (int i = 0; i < (int)(size*nmemb); ++i) {
        if(stream->position == stream->fileSize)
            break;

        if(stream->position/(stream->volume->superSector->sectors_per_cluster*BYTES_PER_SECTOR) > currentCluster)
        {
            currentCluster++;
            disk_read(stream->volume->disk, stream->volume->cluster2_position + (stream->chain->clusters[currentCluster] - 2) * stream->volume->superSector->sectors_per_cluster, cluster, stream->volume->superSector->sectors_per_cluster);
        }

        *((char *)ptr + i) = cluster[stream->position - (currentCluster*(stream->volume->superSector->sectors_per_cluster*BYTES_PER_SECTOR))];
        stream->position++;
        numberOfBlocks++;
    }
    free(cluster);
    return numberOfBlocks/size;
}
int32_t file_seek(struct file_t* stream, int32_t offset, int whence)
{
    if(stream == NULL)
    {
        errno = EFAULT;
        return -1;
    }
    if(whence != SEEK_SET && whence !=SEEK_CUR && whence != SEEK_END)
    {
        errno =EINVAL;
        return -1;
    }
    if(whence == SEEK_SET)
    {
        if(offset>0 && stream->position+offset< stream->fileSize)
        {
            stream->position+=offset;
            return stream->position;
        }
        errno = ENXIO;
    }
    else if(whence == SEEK_END)
    {
        if(offset<0 && stream->fileSize+offset>=0)
        {
            stream->position = stream->fileSize+offset;
            return stream->position;
        }
        errno = ENXIO;
    }
    else
    {
        if(stream->position+offset>=0 && stream->position+offset< stream->fileSize)
        {
            stream->position+=offset;
            return stream->position;
        }
        errno = ENXIO;
    }

    return -1;
}

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector)
{
    if(pdisk == NULL || pdisk->file == NULL)
    {
        errno = EFAULT;
        return NULL;
    }

    struct volume_t *volume = calloc(1,sizeof(struct volume_t));
    if(volume == NULL)
    {
        errno = ENOMEM;
        return NULL;
    }
    volume->superSector = calloc(1,sizeof(struct fat_super_t));
    if(volume->superSector == NULL)
    {
        errno = EFAULT;
        return NULL;
    }
    int res = disk_read(pdisk,0,volume->superSector,1);
    if(res == -1)
    {
        errno = EFAULT;
        return NULL;
    }
    if(volume->superSector->bytes_per_sector !=512)
    {
        free(volume->superSector);
        free(volume);
        errno = EINVAL;
        return NULL;
    }

    volume->fat1_position = 0 + volume->superSector->reserved_sectors;
    volume->fat2_position = 0 + volume->superSector->reserved_sectors + volume->superSector->sectors_per_fat;
    volume->rootdir_position = 0  + volume->superSector->reserved_sectors + volume->superSector->fat_count * volume->superSector->sectors_per_fat;
    volume->sectors_per_rootdir = ((volume->superSector->root_dir_capacity * 32) + (volume->superSector->bytes_per_sector - 1)) / volume->superSector->bytes_per_sector;
    if ((volume->superSector->root_dir_capacity * sizeof(struct fat_entry_t)) % volume->superSector->bytes_per_sector != 0)
        volume->sectors_per_rootdir++;

    volume->cluster2_position = volume->rootdir_position + volume->sectors_per_rootdir;
    volume->volume_size = volume->superSector->logical_sectors16 == 0 ? volume->superSector->logical_sectors32 : volume->superSector->logical_sectors16;
    volume->user_size = volume->volume_size - (volume->superSector->fat_count * volume->superSector->sectors_per_fat) - volume->superSector->reserved_sectors - volume->sectors_per_rootdir;
    volume->number_of_cluster_per_volume = volume->user_size / volume->superSector->sectors_per_cluster;
    volume->disk = pdisk; // tutaj może generować błędy przez przepisywanie wskaźnika

    uint8_t *fat1_data = (uint8_t *) malloc(volume->superSector->bytes_per_sector * volume->superSector->sectors_per_fat);
    uint8_t *fat2_data = (uint8_t *) malloc(volume->superSector->bytes_per_sector * volume->superSector->sectors_per_fat);
    if (fat1_data == NULL || fat2_data == NULL) {
        free(fat1_data);
        free(fat2_data);
        errno = EFAULT;
        return NULL;
    }

    int r1 = disk_read(pdisk, volume->fat1_position,fat1_data, volume->superSector->sectors_per_fat);
    int r2 = disk_read(pdisk, volume->fat2_position,fat2_data, volume->superSector->sectors_per_fat);


    if (r1 == -1 || r2 == -1 || volume->superSector->magic != 0xaa55 || memcmp(fat1_data, fat2_data, volume->superSector->bytes_per_sector * volume->superSector->sectors_per_fat) != 0) {
        free(fat1_data);
        free(fat2_data);
        free(volume->superSector);
        free(volume);
        errno = EINVAL;
        return NULL;
    }

    free(fat1_data);
    free(fat2_data);

    return volume;
}
int fat_close(struct volume_t* pvolume)
{
    if(pvolume != NULL)
    {
        if(pvolume->superSector!=NULL)
            free(pvolume->superSector);
        if(pvolume->disk->file != NULL) {
            fclose(pvolume->disk->file);
            pvolume->disk->file = NULL;
        }
        free(pvolume);
    }
    errno = EFAULT;
    return -1;
}


struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path)
{
    if (pvolume == NULL || dir_path == NULL) {
        errno = EFAULT;
        return NULL;
    }

    struct dir_t *direcory = calloc(1, sizeof(struct dir_t));
    if (direcory == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    if(strcmp(dir_path, "\\") != 0)
    {
        char* sectors = calloc(pvolume->sectors_per_rootdir,BYTES_PER_SECTOR);
        if(sectors == NULL)
        {
            errno = ENOMEM;
            return NULL;
        }
        lba_t numberOfFatEntry = 0;
        struct fat_entry_t *entryFat;
        int notExist = 1;
        char name[14]={0};
        int res = disk_read(pvolume->disk, pvolume->fat2_position + pvolume->superSector->sectors_per_fat, sectors, pvolume->sectors_per_rootdir);
        if (res != (int)pvolume->sectors_per_rootdir) {
            errno = ENOENT;
            return NULL;
        }
        while (numberOfFatEntry*30 < pvolume->sectors_per_rootdir*BYTES_PER_SECTOR)
        {
            memset(name,'\0',14);
            int d = 0;
            for (int i = 0; i < 11; ++i) {
                if(*(sectors + numberOfFatEntry * 32 + i) == '\0')
                    break;
                if(*(sectors + numberOfFatEntry * 32 + i) != ' ' && (*(sectors + numberOfFatEntry * 32 + i) >= 'A' && *(sectors + numberOfFatEntry * 32 + i) <= 'Z' || *(sectors + numberOfFatEntry * 32 + i) == '_')) {
                    *(name + d) = *(sectors + numberOfFatEntry * 32 + i);
                    d++;
                }
            }
            int size = strlen(name);
            if((*(name+size-3)=='T'&&*(name+size-2)=='X'&&*(name+size-1)=='T')||(*(name+size-3)=='B'&&*(name+size-2)=='I'&&*(name+size-1)=='N'))
            {
                for (int i = 0; i < 3; ++i) {
                    *(name+size-i) = *(name+size-i-1);
                }
                *(name+size-3)='.';
            }
            else if(*(name+size-2)=='T'&&*(name+size-1)=='X')
            {
                for (int i = 0; i < 2; ++i) {
                    *(name+size-i) = *(name+size-i-1);
                }
                *(name+size-2)='.';
            }

            if(strcmp(dir_path,name)==0)
            {
                notExist =0;
                break;
            }
            numberOfFatEntry++;
        }

        if(notExist)
        {
            errno = EIO;
            free(sectors);
            free(direcory);
            return NULL;
        }
        int size = strlen(name);
        entryFat = (struct fat_entry_t*)(sectors + numberOfFatEntry * 32);
        if(entryFat->file_size != 0 || (*(name+size-3)=='T'&&*(name+size-2)=='X'&&*(name+size-1)=='T')||(*(name+size-3)=='B'&&*(name+size-2)=='I'&&*(name+size-1)=='N'))
        {
            errno = EISDIR;
            free(sectors);
            free(direcory);
            return NULL;
        }
        direcory->position = numberOfFatEntry;
    }
    direcory->flag = 1;
    direcory->pvolume = pvolume;
    return direcory;
}
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry)
{
    if(pdir == NULL || pentry == NULL)
    {
        errno = EFAULT;
        return -1;
    }

    char* sectors = calloc(pdir->pvolume->sectors_per_rootdir,BYTES_PER_SECTOR);
    if(sectors == NULL)
    {
        errno = ENOMEM;
        return -1;
    }
    char x;

    struct fat_entry_t *entryFat;
    int notExist = 0;
    char name[14]={0};
    int res = disk_read(pdir->pvolume->disk, pdir->pvolume->fat2_position + pdir->pvolume->superSector->sectors_per_fat, sectors, pdir->pvolume->sectors_per_rootdir);
    if (res != (int)pdir->pvolume->sectors_per_rootdir) {
        errno = ENOENT;
        return -1;
    }

    while (pdir->position*30 < (int)pdir->pvolume->sectors_per_rootdir*BYTES_PER_SECTOR)
    {
        memset(name,'\0',14);
        int d = 0;
        for (int i = 0; i < 11; ++i) {
            if(*(sectors + pdir->position * 32 + i) == '\0')
            {
                if(i == 0)
                {
                    errno = EIO;
                    free(sectors);
                    return 1;
                }
                break;
            }
            x = *(sectors + pdir->position * 32 + i);
            if(x == -27){
                pdir->position++;
                i=-1;
                continue;
            }
            if(*(sectors + pdir->position * 32 + i) != ' ' && (*(sectors + pdir->position * 32 + i) >= 'A' && *(sectors + pdir->position * 32 + i) <= 'Z' || *(sectors + pdir->position * 32 + i) == '_')) {
                *(name + d) = *(sectors + pdir->position * 32 + i);
                d++;
            }
        }
        int size = strlen(name);
        if((*(name+size-3)=='T'&&*(name+size-2)=='X'&&*(name+size-1)=='T')||(*(name+size-3)=='B'&&*(name+size-2)=='I'&&*(name+size-1)=='N'))
        {
            for (int i = 0; i < 3; ++i) {
                *(name+size-i) = *(name+size-i-1);
            }
            *(name+size-3)='.';
        }
        else if(*(name+size-2)=='T'&&*(name+size-1)=='X')
        {
            for (int i = 0; i < 2; ++i) {
                *(name+size-i) = *(name+size-i-1);
            }
            *(name+size-2)='.';
        }
        pdir->position++;
        if(pdir->position*30 >= (int)pdir->pvolume->sectors_per_rootdir*BYTES_PER_SECTOR)
            notExist = 1;
        break;
    }

    if(notExist)
    {
        errno = EIO;
        free(sectors);
        return 1;
    }
    entryFat = (struct fat_entry_t*)(sectors + pdir->position * 32);
    memset(pentry,'\0',14);
    strcpy(pentry->name,name);
    pentry->size = entryFat->file_size;
    name[0] =  *(sectors + pdir->position * 32 + 11);
    if(name[0]>=32){
        pentry->is_archived=1;
        name[0]-=32;
    } else
        pentry->is_archived=0;
    if(name[0]>=16){
        pentry->is_directory=1;
        name[0]-=16;
    }else
        pentry->is_directory=0;
    if(name[0]>=4){
        pentry->is_system=1;
        name[0]-=4;
    } else
        pentry->is_system=0;
    if(name[0]>=2){
        pentry->is_hidden=1;
        name[0]-=2;
    }else
        pentry->is_hidden=0;
    if(name[0]>=1){
        pentry->is_readonly=1;
        name[0]-=1;
    }else
        pentry->is_readonly=0;

    // to nie jest istotne
    if(x == -111)
        return 33;
    free(sectors);
    return 0;
}
int dir_close(struct dir_t* pdir)
{
    if(pdir != NULL)
    {
        free(pdir);
        return 0;
    }
    errno = EFAULT;
    return -1;
}





