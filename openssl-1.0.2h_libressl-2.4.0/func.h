#ifndef __FUNC_H__
#define __FUNC_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

/**
 * Caller must free buffer.
 * Return 0 on error, size of file if success
 */
size_t read_file(const char *fn, uint8_t **buf)
{
    struct stat file_status;
    FILE *fp;
    uint8_t *buffer;


    if (stat(fn, &file_status) != 0){
        return 0;
    }

    if ((fp = fopen(fn, "r")) == NULL) {
        return 0;
    }

    buffer = (uint8_t *)malloc(file_status.st_size);
    if (!fread(buffer, file_status.st_size, 1, fp)) {
        fclose(fp);
        free(buffer);
        return 0;
    }

    *buf = buffer;
    fclose(fp);
    return file_status.st_size;
}

#endif  //__FUNC_H__
