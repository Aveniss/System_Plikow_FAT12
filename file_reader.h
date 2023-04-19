//
// Created by kamil on 04.01.2023.
//

#ifndef UNTITLED8_FILE_READER_H
#define UNTITLED8_FILE_READER_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define BYTES_PER_SECTOR    512
typedef uint32_t lba_t;

struct clusters_chain_t {
    uint16_t *clusters;
    size_t size;
};

struct data
{
    unsigned int day_hour;
    unsigned int month_minute;
    unsigned int year_second;
};
struct dir_entry_t {
    char name[14];
    u_int32_t size;
    int is_archived;
    int is_readonly;
    int is_system;
    int is_hidden;
    int is_directory;
    struct data creation_date;
    struct data creation_time;
};

struct fat_super_t {
    uint8_t __jump_code[3];
    char oem_name[8];

    //
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_dir_capacity;
    uint16_t logical_sectors16;
    uint8_t __reserved;
    uint16_t sectors_per_fat;

    uint32_t __reserved2;

    uint32_t hidden_sectors;
    uint32_t logical_sectors32;

    uint16_t __reserved3;
    uint8_t __reserved4;

    uint32_t serial_number;

    char label[11];
    char fsid[8];

    uint8_t __boot_code[448];
    uint16_t magic; // 55 aa
} __attribute__(( packed ));

enum fat_attribute_t {
    FAT_DIRECTORY = 0x10,
    FAT_VOLUME_LABEL = 0x08,
} __attribute__(( packed ));

#define FAT_DELETED_MAGIC ((char)0xE5)

struct fat_entry_t {
    char name[11];
    enum fat_attribute_t attributes;

    uint8_t __some_data[6]; // todo: do wczytania później
    uint16_t __some_data2;

    uint16_t high_cluster_index;
    uint16_t __some_data3[2];
    uint16_t low_cluster_index;
    uint32_t file_size;

} __attribute__(( packed ));




struct disk_t
{
    FILE *file;
};
struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);


struct volume_t
{
    lba_t fat1_position;
    lba_t fat2_position;
    lba_t rootdir_position ;
    lba_t sectors_per_rootdir;
    lba_t cluster2_position;
    lba_t volume_size ;
    lba_t user_size ;
    lba_t number_of_cluster_per_volume ;
    struct fat_super_t *superSector;
    struct disk_t *disk;
}__attribute__ (( packed ));
struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector);
int fat_close(struct volume_t* pvolume);



struct file_t
{
    struct volume_t *volume;
    struct clusters_chain_t *chain;
    int position;
    int fileSize;
};

struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);

struct dir_t
{
    int position;
    int flag;
    struct volume_t *pvolume;
};


struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);
#endif //UNTITLED8_FILE_READER_H
