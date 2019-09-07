#include "aegis256.c"
#include "stdio.h"

#define COUNT(x) (sizeof(x) / sizeof(x[0]))

struct {
    unsigned char *key;
    unsigned char *npub;
    unsigned char *m;
    unsigned int mlen;
    unsigned char *ad;
    unsigned int adlen;
    unsigned char *c;
} t[] = {
    {
        .key = "\x0f\xc9\x8e\x67\x44\x9e\xaa\x86"
               "\x20\x36\x2c\x24\xfe\xc9\x30\x81"
               "\xca\xb0\x82\x21\x41\xa8\xe0\x06"
               "\x30\x0b\x37\xf6\xb6\x17\xe7\xb5",
        .npub = "\x1e\x92\x1c\xcf\x88\x3d\x54\x0d"
                "\x40\x6d\x59\x48\xfc\x92\x61\x03"
                "\x95\x61\x05\x42\x82\x50\xc0\x0c"
                "\x60\x16\x6f\xec\x6d\x2f\xcf\x6b",
        .ad = "",
        .adlen = 0,
        .m = "",
        .mlen = 0,
        .c = "\xd5\x65\x3a\xa9\x03\x51\xd7\xaa"
             "\xfa\x4b\xd8\xa2\x41\x9b\xc1\xb2",
    },
    {
        .key = "\x4b\xed\xc8\x07\x54\x1a\x52\xa2"
               "\xa1\x10\xde\xb5\xf8\xed\xf3\x87"
               "\xf4\x72\x8e\xa5\x46\x48\x62\x20"
               "\xf1\x38\x16\xce\x90\x76\x87\x8c",
        .npub = "\x5a\xb7\x56\x6e\x98\xb9\xfd\x29"
                "\xc1\x47\x0b\xda\xf6\xb6\x23\x09"
                "\xbf\x23\x11\xc6\x87\xf0\x42\x26"
                "\x22\x44\x4e\xc4\x47\x8e\x6e\x41",
        .ad = "",
        .adlen = 0,
        .m = "\x79",
        .mlen = 1,
        .c = "\x84\xa2\x8f\xad\xdb\x8d\x2c\x16"
             "\x9e\x89\xd9\x06\xa6\xa8\x14\x29"
             "\x8b",
    },
    {
        .key = "\x88\x12\x01\xa6\x64\x96\xfb\xbe"
               "\x22\xea\x90\x47\xf2\x11\xb5\x8e"
               "\x1f\x35\x9a\x29\x4b\xe8\xe4\x39"
               "\xb3\x66\xf5\xa6\x6a\xd5\x26\x62",
        .npub = "\x97\xdb\x90\x0e\xa8\x35\xa5\x45"
                "\x42\x21\xbd\x6b\xf0\xda\xe6\x0f"
                "\xe9\xe5\x1d\x4a\x8c\x90\xc4\x40"
                "\xe3\x71\x2d\x9c\x21\xed\x0e\x18",
        .ad = "",
        .adlen = 0,
        .m = "\xb5\x6e\xad\xdd\x30\x72\xfa\x53"
             "\x82\x8e\x16\xb4\xed\x6d\x47",
        .mlen = 15,
        .c = "\x09\x94\x1f\xa6\x13\xc3\x74\x75"
             "\x17\xad\x8a\x0e\xd8\x66\x9a\x28"
             "\xd7\x30\x66\x09\x2a\xdc\xfa\x2a"
             "\x9f\x3b\xd7\xdd\x66\xd1\x2b",
    },
    {
        .key = "\xc4\x37\x3b\x45\x74\x11\xa4\xda"
               "\xa2\xc5\x42\xd8\xec\x36\x78\x94"
               "\x49\xf7\xa5\xad\x50\x88\x66\x53"
               "\x74\x94\xd4\x7f\x44\x34\xc5\x39",
        .npub = "\xd3\x00\xc9\xad\xb8\xb0\x4e\x61"
                "\xc3\xfb\x6f\xfd\xea\xff\xa9\x15"
                "\x14\xa8\x28\xce\x92\x30\x46\x59"
                "\xa4\x9f\x0b\x75\xfb\x4c\xad\xee",
        .ad = "",
        .adlen = 0,
        .m = "\xf2\x92\xe6\x7d\x40\xee\xa3\x6f"
             "\x03\x68\xc8\x45\xe7\x91\x0a\x18",
        .mlen = 16,
        .c = "\x8a\x46\xa2\x22\x8c\x03\xab\x6f"
             "\x54\x63\x4e\x7f\xc9\x8e\xfa\x70"
             "\x7b\xe5\x8d\x78\xbc\xe9\xb6\xa1"
             "\x29\x17\xc8\x3b\x52\xa4\x98\x72",
    },
    {
        .key = "\x01\x5c\x75\xe5\x84\x8d\x4d\xf6"
               "\x23\x9f\xf4\x6a\xe6\x5a\x3b\x9a"
               "\x74\xb9\xb1\x32\x55\x28\xe8\x6d"
               "\x35\xc1\xb3\x57\x1f\x93\x64\x0f",
        .npub = "\x10\x25\x03\x4c\xc8\x2c\xf7\x7d"
                "\x44\xd5\x21\x8e\xe4\x23\x6b\x1c"
                "\x3e\x6a\x34\x53\x97\xd0\xc8\x73"
                "\x66\xcd\xea\x4d\xd5\xab\x4c\xc5",
        .ad = "",
        .adlen = 0,
        .m = "\x2e\xb7\x20\x1c\x50\x6a\x4b\x8b"
             "\x84\x42\x7a\xd7\xe1\xb5\xcd\x1f"
             "\xd3",
        .mlen = 17,
        .c = "\x71\x6b\x37\x0b\x02\x61\x28\x12"
             "\x83\xab\x66\x90\x84\xc7\xd1\xc5"
             "\xb2\x7a\xb4\x7b\xb4\xfe\x02\xb2"
             "\xc0\x00\x39\x13\xb5\x51\x68\x44"
             "\xad",
    },
    {
        .key = "\x3d\x80\xae\x84\x94\x09\xf6\x12"
               "\xa4\x79\xa6\xfb\xe0\x7f\xfd\xa0"
               "\x9e\x7c\xbc\xb6\x5b\xc8\x6a\x86"
               "\xf7\xef\x91\x30\xf9\xf2\x04\xe6",
        .npub = "\x4c\x49\x3d\xec\xd8\xa8\xa0\x98"
                "\xc5\xb0\xd3\x1f\xde\x48\x2e\x22"
                "\x69\x2c\x3f\xd7\x9c\x70\x4a\x8d"
                "\x27\xfa\xc9\x26\xaf\x0a\xeb\x9c",
        .ad = "",
        .adlen = 0,
        .m = "\x6b\xdc\x5a\xbb\x60\xe5\xf4\xa6"
             "\x05\x1d\x2c\x68\xdb\xda\x8f\x25"
             "\xfe\x8d\x45\x19\x1e\xc0\x0b\x99"
             "\x88\x11\x39\x12\x1c\x3a\xbb",
        .mlen = 31,
        .c = "\xaf\xa4\x34\x0d\x59\xe6\x1c\x2f"
             "\x06\x3b\x52\x18\x49\x75\x1b\xf0"
             "\x53\x09\x72\x7b\x45\x79\xe0\xbe"
             "\x89\x85\x23\x15\xb8\x79\x07\x4c"
             "\x53\x7a\x15\x37\x0a\xee\xb7\xfb"
             "\xc4\x1f\x12\x27\xcf\x77\x90",
    },
    {
        .key = "\x7a\xa5\xe8\x23\xa4\x84\x9e\x2d"
               "\x25\x53\x58\x8c\xda\xa3\xc0\xa6"
               "\xc8\x3e\xc8\x3a\x60\x68\xec\xa0"
               "\xb8\x1c\x70\x08\xd3\x51\xa3\xbd",
        .npub = "\x89\x6e\x77\x8b\xe8\x23\x49\xb4"
                "\x45\x8a\x85\xb1\xd8\x6c\xf1\x28"
                "\x93\xef\x4b\x5b\xa1\x10\xcc\xa6"
                "\xe8\x28\xa8\xfe\x89\x69\x8b\x72",
        .ad = "",
        .adlen = 0,
        .m = "\xa7\x00\x93\x5b\x70\x61\x9d\xc2"
             "\x86\xf7\xde\xfa\xd5\xfe\x52\x2b"
             "\x28\x50\x51\x9d\x24\x60\x8d\xb3"
             "\x49\x3e\x17\xea\xf6\x99\x5a\xdd",
        .mlen = 32,
        .c = "\xe2\xc9\x0b\x33\x31\x02\xb3\xb4"
             "\x33\xfe\xeb\xa8\xb7\x9b\xb2\xd7"
             "\xeb\x0f\x05\x2b\xba\xb3\xca\xef"
             "\xf6\xd1\xb6\xc0\xb9\x9b\x85\xc5"
             "\xbf\x7a\x3e\xcc\x31\x76\x09\x80"
             "\x32\x5d\xbb\xe8\x38\x0e\x77\xd3",
    },
    {
        .key = "\xb6\xca\x22\xc3\xb4\x00\x47\x49"
               "\xa6\x2d\x0a\x1e\xd4\xc7\x83\xad"
               "\xf3\x00\xd4\xbf\x65\x08\x6e\xb9"
               "\x7a\x4a\x4f\xe0\xad\xb0\x42\x93",
        .npub = "\xc5\x93\xb0\x2a\xf8\x9f\xf1\xd0"
                "\xc6\x64\x37\x42\xd2\x90\xb3\x2e"
                "\xbd\xb1\x57\xe0\xa6\xb0\x4e\xc0"
                "\xaa\x55\x87\xd6\x63\xc8\x2a\x49",
        .ad = "\xd5",
        .adlen = 1,
        .m = "",
        .mlen = 0,
        .c = "\x96\x43\x30\xca\x6c\x4f\xd7\x12"
             "\xba\xd9\xb3\x18\x86\xdf\xc3\x52",
    },
    {
        .key = "\xf3\xee\x5c\x62\xc4\x7c\xf0\x65"
               "\x27\x08\xbd\xaf\xce\xec\x45\xb3"
               "\x1d\xc3\xdf\x43\x6a\xa8\xf0\xd3"
               "\x3b\x77\x2e\xb9\x87\x0f\xe1\x6a",
        .npub = "\x02\xb8\xea\xca\x09\x1b\x9a\xec"
                "\x47\x3e\xe9\xd4\xcc\xb5\x76\x34"
                "\xe8\x73\x62\x64\xab\x50\xd0\xda"
                "\x6b\x83\x66\xaf\x3e\x27\xc9\x1f",
        .ad = "\x11\x81\x78\x32\x4d\xb9\x44\x73"
              "\x68\x75\x16\xf8\xcb\x7e\xa7",
        .adlen = 15,
        .m = "",
        .mlen = 0,
        .c = "\x2f\xab\x45\xe2\xa7\x46\xc5\x83"
             "\x11\x9f\xb0\x74\xee\xc7\x03\xdd",
    },
    {
        .key = "\x2f\x13\x95\x01\xd5\xf7\x99\x81"
               "\xa8\xe2\x6f\x41\xc8\x10\x08\xb9"
               "\x47\x85\xeb\xc7\x6f\x48\x72\xed"
               "\xfc\xa5\x0d\x91\x61\x6e\x81\x40",
        .npub = "\x3f\xdc\x24\x69\x19\x96\x43\x08"
                "\xc8\x18\x9b\x65\xc6\xd9\x39\x3b"
                "\x12\x35\x6e\xe8\xb0\xf0\x52\xf3"
                "\x2d\xb0\x45\x87\x18\x86\x68\xf6",
        .ad = "\x4e\xa5\xb2\xd1\x5d\x35\xed\x8f"
              "\xe8\x4f\xc8\x89\xc5\xa2\x69\xbc",
        .adlen = 16,
        .m = "",
        .mlen = 0,
        .c = "\x16\x44\x73\x33\x5d\xf2\xb9\x04"
             "\x6b\x79\x98\xef\xdb\xd5\xc5\xf1",
    },
    {
        .key = "\x6c\x38\xcf\xa1\xe5\x73\x41\x9d"
               "\x29\xbc\x21\xd2\xc2\x35\xcb\xbf"
               "\x72\x47\xf6\x4b\x74\xe8\xf4\x06"
               "\xbe\xd3\xec\x6a\x3b\xcd\x20\x17",
        .npub = "\x7b\x01\x5d\x08\x29\x12\xec\x24"
                "\x49\xf3\x4d\xf7\xc0\xfe\xfb\x41"
                "\x3c\xf8\x79\x6c\xb6\x90\xd4\x0d"
                "\xee\xde\x23\x60\xf2\xe5\x08\xcc",
        .ad = "\x8a\xca\xec\x70\x6d\xb1\x96\xab"
              "\x69\x29\x7a\x1b\xbf\xc7\x2c\xc2"
              "\x07",
        .adlen = 17,
        .m = "",
        .mlen = 0,
        .c = "\xa4\x9b\xb8\x47\xc0\xed\x7a\x45"
             "\x98\x54\x8c\xed\x3d\x17\xf0\xdd",
    },
    {
        .key = "\xa8\x5c\x09\x40\xf5\xef\xea\xb8"
               "\xaa\x96\xd3\x64\xbc\x59\x8d\xc6"
               "\x9c\x0a\x02\xd0\x79\x88\x76\x20"
               "\x7f\x00\xca\x42\x15\x2c\xbf\xed",
        .npub = "\xb8\x26\x97\xa8\x39\x8e\x94\x3f"
                "\xca\xcd\xff\x88\xba\x22\xbe\x47"
                "\x67\xba\x85\xf1\xbb\x30\x56\x26"
                "\xaf\x0b\x02\x38\xcc\x44\xa7\xa3",
        .ad = "\xc7\xef\x26\x10\x7d\x2c\x3f\xc6"
              "\xea\x03\x2c\xac\xb9\xeb\xef\xc9"
              "\x31\x6b\x08\x12\xfc\xd8\x37\x2d"
              "\xe0\x17\x3a\x2e\x83\x5c\x8f",
        .adlen = 31,
        .m = "",
        .mlen = 0,
        .c = "\x20\x24\xe2\x33\x5c\x60\xc9\xf0"
             "\xa4\x96\x2f\x0d\x53\xc2\xf8\xfc",
    },
    {
        .key = "\xe5\x81\x42\xdf\x05\x6a\x93\xd4"
               "\x2b\x70\x85\xf5\xb6\x7d\x50\xcc"
               "\xc6\xcc\x0e\x54\x7f\x28\xf8\x3a"
               "\x40\x2e\xa9\x1a\xf0\x8b\x5e\xc4",
        .npub = "\xf4\x4a\xd1\x47\x49\x09\x3d\x5b"
                "\x4b\xa7\xb1\x19\xb4\x46\x81\x4d"
                "\x91\x7c\x91\x75\xc0\xd0\xd8\x40"
                "\x71\x39\xe1\x10\xa6\xa3\x46\x7a",
        .ad = "\x03\x14\x5f\xaf\x8d\xa8\xe7\xe2"
              "\x6b\xde\xde\x3e\xb3\x10\xb1\xcf"
              "\x5c\x2d\x14\x96\x01\x78\xb9\x47"
              "\xa1\x44\x19\x06\x5d\xbb\x2e\x2f",
        .adlen = 32,
        .m = "",
        .mlen = 0,
        .c = "\x6f\x4a\xb9\xe0\xff\x51\xa3\xf1"
             "\xd2\x64\x3e\x66\x6a\xb2\x03\xc0",
    },
    {
        .key = "\x22\xa6\x7c\x7f\x15\xe6\x3c\xf0"
               "\xac\x4b\x37\x86\xb0\xa2\x13\xd2"
               "\xf1\x8e\x19\xd8\x84\xc8\x7a\x53"
               "\x02\x5b\x88\xf3\xca\xea\xfe\x9b",
        .npub = "\x31\x6f\x0b\xe6\x59\x85\xe6\x77"
                "\xcc\x81\x63\xab\xae\x6b\x43\x54"
                "\xbb\x3f\x9c\xf9\xc5\x70\x5a\x5a"
                "\x32\x67\xc0\xe9\x80\x02\xe5\x50",
        .ad = "\x40",
        .adlen = 1,
        .m = "\x4f",
        .mlen = 1,
        .c = "\x2c\xfb\xad\x7e\xbe\xa0\x9a\x5b"
             "\x7a\x3f\x81\xf7\xfc\x1b\x79\x83"
             "\xc7",
    },
    {
        .key = "\x5e\xcb\xb6\x1e\x25\x62\xe4\x0c"
               "\x2d\x25\xe9\x18\xaa\xc6\xd5\xd8"
               "\x1b\x50\x25\x5d\x89\x68\xfc\x6d"
               "\xc3\x89\x67\xcb\xa4\x49\x9d\x71",
        .npub = "\x6d\x94\x44\x86\x69\x00\x8f\x93"
                "\x4d\x5b\x15\x3c\xa8\x8f\x06\x5a"
                "\xe6\x01\xa8\x7e\xca\x10\xdc\x73"
                "\xf4\x94\x9f\xc1\x5a\x61\x85\x27",
        .ad = "\x7c\x5d\xd3\xee\xad\x9f\x39\x1a"
              "\x6d\x92\x42\x61\xa7\x58\x37",
        .adlen = 15,
        .m = "\x8b\x26\x61\x55\xf1\x3e\xe3\xa1"
             "\x8d\xc8\x6e\x85\xa5\x21\x67",
        .mlen = 15,
        .c = "\x1f\x7f\xca\x3c\x2b\xe7\x27\xba"
             "\x7e\x98\x83\x02\x34\x23\xf7\x94"
             "\xde\x35\xe6\x1d\x14\x18\xe5\x38"
             "\x14\x80\x6a\xa7\x1b\xae\x1d",
    },
    {
        .key = "\x9b\xef\xf0\xbd\x35\xdd\x8d\x28"
               "\xad\xff\x9b\xa9\xa4\xeb\x98\xdf"
               "\x46\x13\x31\xe1\x8e\x08\x7e\x87"
               "\x85\xb6\x46\xa3\x7e\xa8\x3c\x48",
        .npub = "\xaa\xb8\x7e\x25\x79\x7c\x37\xaf"
                "\xce\x36\xc7\xce\xa2\xb4\xc9\x60"
                "\x10\xc3\xb3\x02\xcf\xb0\x5e\x8d"
                "\xb5\xc2\x7e\x9a\x35\xc0\x24\xfd",
        .ad = "\xb9\x82\x0c\x8d\xbd\x1b\xe2\x36"
              "\xee\x6c\xf4\xf2\xa1\x7d\xf9\xe2",
        .adlen = 16,
        .m = "\xc8\x4b\x9b\xf5\x01\xba\x8c\xbd"
             "\x0e\xa3\x21\x16\x9f\x46\x2a\x63",
        .mlen = 16,
        .c = "\x05\x86\x9e\xd7\x2b\xa3\x97\x01"
             "\xbe\x28\x98\x10\x6f\xe9\x61\x32"
             "\x96\xbb\xb1\x2e\x8f\x0c\x44\xb9"
             "\x46\x2d\x55\xe3\x42\x67\xf2\xaf",
    },
    {
        .key = "\xd7\x14\x29\x5d\x45\x59\x36\x44"
               "\x2e\xd9\x4d\x3b\x9e\x0f\x5b\xe5"
               "\x70\xd5\x3c\x65\x93\xa8\x00\xa0"
               "\x46\xe4\x25\x7c\x58\x08\xdb\x1e",
        .npub = "\xe6\xdd\xb8\xc4\x89\xf8\xe0\xca"
                "\x4f\x10\x7a\x5f\x9c\xd8\x8b\x66"
                "\x3b\x86\xbf\x86\xd4\x50\xe0\xa7"
                "\x76\xef\x5c\x72\x0f\x1f\xc3\xd4",
        .ad = "\xf5\xa6\x46\x2c\xce\x97\x8a\x51"
              "\x6f\x46\xa6\x83\x9b\xa1\xbc\xe8"
              "\x05",
        .adlen = 17,
        .m = "\x05\x70\xd5\x94\x12\x36\x35\xd8"
             "\x8f\x7d\xd3\xa8\x99\x6a\xed\x69"
             "\xd0",
        .mlen = 17,
        .c = "\x9c\xe0\x06\x7b\x86\xcf\x2e\xd8"
             "\x45\x65\x1b\x72\x9b\xaa\xa3\x1e"
             "\x87\x9d\x26\xdf\xff\x81\x11\xd2"
             "\x47\x41\xb9\x24\xc1\x8a\xa3\x8b"
             "\x55",
    },
    {
        .key = "\x14\x39\x63\xfc\x56\xd5\xdf\x5f"
               "\xaf\xb3\xff\xcc\x98\x33\x1d\xeb"
               "\x9a\x97\x48\xe9\x98\x48\x82\xba"
               "\x07\x11\x04\x54\x32\x67\x7b\xf5",
        .npub = "\x23\x02\xf1\x64\x9a\x73\x89\xe6"
                "\xd0\xea\x2c\xf1\x96\xfc\x4e\x6d"
                "\x65\x48\xcb\x0a\xda\xf0\x62\xc0"
                "\x38\x1d\x3b\x4a\xe9\x7e\x62\xaa",
        .ad = "\x32\xcb\x80\xcc\xde\x12\x33\x6d"
              "\xf0\x20\x58\x15\x95\xc6\x7f\xee"
              "\x2f\xf9\x4e\x2c\x1b\x98\x43\xc7"
              "\x68\x28\x73\x40\x9f\x96\x4a",
        .adlen = 31,
        .m = "\x41\x94\x0e\x33\x22\xb1\xdd\xf4"
             "\x10\x57\x85\x39\x93\x8f\xaf\x70"
             "\xfa\xa9\xd0\x4d\x5c\x40\x23\xcd"
             "\x98\x34\xab\x37\x56\xae\x32",
        .mlen = 31,
        .c = "\xa0\xc8\xde\x83\x0d\xc3\x4e\xd5"
             "\x69\x7f\x7a\xdd\x8c\x46\xda\xba"
             "\x0a\x5c\x0e\x7f\xac\xee\x02\xd2"
             "\xe5\x4b\x0a\xba\xb8\xa4\x7b\x66"
             "\xde\xae\xdb\xc2\xc0\x0b\xf7\x2b"
             "\xdf\xb8\xea\xd8\xa9\x38\xed",
    },
    {
        .key = "\x50\x5d\x9d\x9b\x66\x50\x88\x7b"
               "\x30\x8e\xb1\x5e\x92\x58\xe0\xf1"
               "\xc5\x5a\x53\x6e\x9d\xe8\x04\xd4"
               "\xc9\x3f\xe2\x2d\x0c\xc6\x1a\xcb",
        .npub = "\x5f\x27\x2b\x03\xaa\xef\x32\x02"
                "\x50\xc4\xde\x82\x90\x21\x11\x73"
                "\x8f\x0a\xd6\x8f\xdf\x90\xe4\xda"
                "\xf9\x4a\x1a\x23\xc3\xdd\x02\x81",
        .ad = "\x6e\xf0\xba\x6b\xee\x8e\xdc\x89"
              "\x71\xfb\x0a\xa6\x8f\xea\x41\xf4"
              "\x5a\xbb\x59\xb0\x20\x38\xc5\xe0"
              "\x29\x56\x52\x19\x79\xf5\xe9\x37",
        .adlen = 32,
        .m = "\x7e\xb9\x48\xd3\x32\x2d\x86\x10"
             "\x91\x31\x37\xcb\x8d\xb3\x72\x76"
             "\x24\x6b\xdc\xd1\x61\xe0\xa5\xe7"
             "\x5a\x61\x8a\x0f\x30\x0d\xd1\xec",
        .mlen = 32,
        .c = "\xd3\x68\x14\x70\x3c\x01\x43\x86"
             "\x02\xab\xbe\x75\xaa\xe7\xf5\x53"
             "\x5c\x05\xbd\x9b\x19\xbb\x2a\x61"
             "\x8f\x69\x05\x75\x8e\xca\x60\x0c"
             "\x5b\xa2\x48\x61\x32\x74\x11\x2b"
             "\xf6\xcf\x06\x78\x6f\x78\x1a\x4a",
    },
    {
        .key = "\x8d\x82\xd6\x3b\x76\xcc\x30\x97"
               "\xb1\x68\x63\xef\x8c\x7c\xa3\xf7"
               "\xef\x1c\x5f\xf2\xa3\x88\x86\xed"
               "\x8a\x6d\xc1\x05\xe7\x25\xb9\xa2",
        .npub = "\x9c\x4b\x65\xa2\xba\x6b\xdb\x1e"
                "\xd1\x9e\x90\x13\x8a\x45\xd3\x79"
                "\xba\xcd\xe2\x13\xe4\x30\x66\xf4"
                "\xba\x78\xf9\xfb\x9d\x3c\xa1\x58",
        .ad = "\xab\x14\xf3\x0a\xfe\x0a\x85\xa5"
              "\xf2\xd5\xbc\x38\x89\x0e\x04\xfb"
              "\x84\x7d\x65\x34\x25\xd8\x47\xfa"
              "\xeb\x83\x31\xf1\x54\x54\x89\x0d"
              "\x9d",
        .adlen = 33,
        .m = "\xba\xde\x82\x72\x42\xa9\x2f\x2c"
             "\x12\x0b\xe9\x5c\x87\xd7\x35\x7c"
             "\x4f\x2e\xe8\x55\x66\x80\x27\x00"
             "\x1b\x8f\x68\xe7\x0a\x6c\x71\xc3"
             "\x21\x78\x55\x9d\x9c\x65\x7b\xcd"
             "\x0a\x34\x97\xff\x47\x37\xb0\x2a"
             "\x80\x0d\x19\x98\x33\xa9\x7a\xe3"
             "\x2e\x4c\xc6\xf3\x8c\x88\x42\x01"
             "\xbd",
        .mlen = 65,
        .c = "\x07\x0a\x35\xb0\x82\x03\x5a\xd2"
             "\x15\x3a\x6c\x72\x83\x9b\xb1\x75"
             "\xea\xf2\xfc\xff\xc6\xf1\x13\xa4"
             "\x1a\x93\x33\x79\x97\x82\x81\xc0"
             "\x96\xc2\x00\xab\x39\xae\xa1\x62"
             "\x53\xa3\x86\xc9\x07\x8c\xaf\x22"
             "\x47\x31\x29\xca\x4a\x95\xf5\xd5"
             "\x20\x63\x5a\x54\x80\x2c\x4a\x63"
             "\xfb\x18\x73\x31\x4f\x08\x21\x5d"
             "\x20\xe9\xc3\x7e\xea\x25\x77\x3a"
             "\x65",
    },
    {
        .key = "\xc9\xa7\x10\xda\x86\x48\xd9\xb3"
               "\x32\x42\x15\x80\x85\xa1\x65\xfe"
               "\x19\xde\x6b\x76\xa8\x28\x08\x07"
               "\x4b\x9a\xa0\xdd\xc1\x84\x58\x79",
        .npub = "\xd8\x70\x9f\x42\xca\xe6\x83\x3a"
                "\x52\x79\x42\xa5\x84\x6a\x96\x7f"
                "\xe4\x8f\xed\x97\xe9\xd0\xe8\x0d"
                "\x7c\xa6\xd8\xd4\x77\x9b\x40\x2e",
        .ad = "\xe8\x39\x2d\xaa\x0e\x85\x2d\xc1"
              "\x72\xaf\x6e\xc9\x82\x33\xc7\x01"
              "\xaf\x40\x70\xb8\x2a\x78\xc9\x14"
              "\xac\xb1\x10\xca\x2e\xb3\x28\xe4"
              "\xac\xfa\x58\x7f\xe5\x73\x09\x8c"
              "\x1d\x40\x87\x8c\xd9\x75\xc0\x55"
              "\xa2\xda\x07\xd1\xc2\xa9\xd1\xbb"
              "\x09\x4f\x77\x62\x88\x2d\xf2\x68"
              "\x54",
        .adlen = 65,
        .m = "\xf7\x02\xbb\x11\x52\x24\xd8\x48"
             "\x93\xe6\x9b\xee\x81\xfc\xf7\x82"
             "\x79\xf0\xf3\xd9\x6c\x20\xa9\x1a"
             "\xdc\xbc\x47\xc0\xe4\xcb\x10\x99"
             "\x2f",
        .mlen = 33,
        .c = "\x33\xc1\xda\xfa\x15\x21\x07\x8e"
             "\x93\x68\xea\x64\x7b\x3d\x4b\x6b"
             "\x71\x5e\x5e\x6b\x92\xaa\x65\xc2"
             "\x7a\x2a\xc1\xa9\x0a\xa1\x24\x81"
             "\x26\x3a\x5a\x09\xe8\xce\x73\x72"
             "\xde\x7b\x58\x9e\x85\xb9\xa4\x28"
             "\xda",
    },
    {
        .key = "\x06\xcc\x4a\x79\x96\xc3\x82\xcf"
               "\xb3\x1c\xc7\x12\x7f\xc5\x28\x04"
               "\x44\xa1\x76\xfb\xad\xc8\x8a\x21"
               "\x0d\xc8\x7f\xb6\x9b\xe3\xf8\x4f",
        .npub = "\x15\x95\xd8\xe1\xda\x62\x2c\x56"
                "\xd3\x53\xf4\x36\x7e\x8e\x59\x85"
                "\x0e\x51\xf9\x1c\xee\x70\x6a\x27"
                "\x3d\xd3\xb7\xac\x51\xfa\xdf\x05",
        .ad = "\x24\x5e\x67\x49\x1e\x01\xd6\xdd"
              "\xf3\x89\x20\x5b\x7c\x57\x89\x07",
        .adlen = 16,
        .m = "\x33\x27\xf5\xb1\x62\xa0\x80\x63"
             "\x14\xc0\x4d\x7f\x7b\x20\xba\x89",
        .mlen = 16,
        .c = "\x3e\xf8\x86\x3d\x39\xf8\x96\x02"
             "\x0f\xdf\xc9\x6e\x37\x1e\x57\x99"
             "\x07\x2a\x1a\xac\xd1\xda\xfd\x3b"
             "\xc7\xff\xbd\xbc\x85\x09\x0b\xab",
    },
    {
        .key = "\x42\xf0\x84\x19\xa6\x3f\x2b\xea"
               "\x34\xf6\x79\xa3\x79\xe9\xeb\x0a"
               "\x6e\x63\x82\x7f\xb2\x68\x0c\x3a"
               "\xce\xf5\x5e\x8e\x75\x42\x97\x26",
        .npub = "\x51\xb9\x12\x80\xea\xde\xd5\x71"
                "\x54\x2d\xa6\xc8\x78\xb2\x1b\x8c"
                "\x39\x14\x05\xa0\xf3\x10\xec\x41"
                "\xff\x01\x95\x84\x2b\x59\x7f\xdb",
        .ad = "\x61\x83\xa0\xe8\x2e\x7d\x7f\xf8"
              "\x74\x63\xd2\xec\x76\x7c\x4c\x0d",
        .adlen = 16,
        .m = "\x70\x4c\x2f\x50\x72\x1c\x29\x7f"
             "\x95\x9a\xff\x10\x75\x45\x7d\x8f",
        .mlen = 16,
        .c = "\x2f\xc4\xd8\x0d\xa6\x07\xef\x2e"
             "\x6c\xd9\x84\x63\x70\x97\x61\x37"
             "\x08\x2f\x16\x90\x9e\x62\x30\x0d"
             "\x62\xd5\xc8\xf0\x46\x1a\x24\x4f",
    },
    {
        .key = "\x7f\x15\xbd\xb8\xb6\xba\xd3\x06"
               "\xb5\xd1\x2b\x35\x73\x0e\xad\x10"
               "\x98\x25\x8d\x03\xb7\x08\x8e\x54"
               "\x90\x23\x3d\x67\x4f\xa1\x36\xfc",
        .npub = "\x8e\xde\x4c\x20\xfa\x59\x7e\x8d"
                "\xd5\x07\x58\x59\x72\xd7\xde\x92"
                "\x63\xd6\x10\x24\xf8\xb0\x6e\x5a"
                "\xc0\x2e\x74\x5d\x06\xb8\x1e\xb2",
        .ad = "\x9d\xa7\xda\x88\x3e\xf8\x28\x14"
              "\xf5\x3e\x85\x7d\x70\xa0\x0f\x13",
        .adlen = 16,
        .m = "\xac\x70\x69\xef\x82\x97\xd2\x9b"
             "\x15\x74\xb1\xa2\x6f\x69\x3f\x95",
        .mlen = 16,
        .c = "\xce\xf3\x17\x87\x49\xc2\x00\x46"
             "\xc6\x12\x5c\x8f\x81\x38\xaa\x55"
             "\xf8\x67\x75\xf1\x75\xe3\x2a\x24"
             "\x90\x13\x5e\xaa\x31\xa1\xdb\xbe",
    },
};

int
main(int argc, char **argv)
{
    int ret = 0;

    printf("encrypt:\n");

    for (int i = 0; i < COUNT(t); i++) {
        unsigned char c[1024] = {0};
        unsigned long long clen = 0;

        int r = aegis256_encrypt(c, &clen,
                                 t[i].m,
                                 t[i].mlen,
                                 t[i].ad,
                                 t[i].adlen,
                                 t[i].npub,
                                 t[i].key);

        if (r || clen != t[i].mlen + 16 || memcmp(t[i].c, c, clen)) {
            printf("%3i: FAILED\n", i);
            ret = 1;
        } else {
            printf("%3i: OK\n", i);
        }
    }

    printf("decrypt:\n");

    for (int i = 0; i < COUNT(t); i++) {
        unsigned char m[1024] = {0};
        unsigned long long mlen = sizeof(m);

        int r = aegis256_decrypt(m, &mlen,
                                 t[i].c,
                                 t[i].mlen + 16,
                                 t[i].ad,
                                 t[i].adlen,
                                 t[i].npub,
                                 t[i].key);

        if (r || mlen != t[i].mlen || memcmp(t[i].m, m, mlen)) {
            printf("%3i: FAILED\n", i);
            ret = 1;
        } else {
            printf("%3i: OK\n", i);
        }
    }

    return ret;
}
