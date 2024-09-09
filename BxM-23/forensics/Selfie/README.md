# Selfie

#### We are given a file named BxMCTF-Foren-1.jpg

![Image](assets/BxMCTF-Foren-1.jpg)

# Analysis

```bash
ExifTool Version Number         : 12.40
File Name                       : BxMCTF-Foren-1.jpg
Directory                       : .
File Size                       : 68 KiB
File Modification Date/Time     : 2023:05:21 16:46:28+07:00
File Access Date/Time           : 2023:06:02 11:21:32+07:00
File Inode Change Date/Time     : 2023:06:02 11:20:52+07:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
XMP Toolkit                     : Image::ExifTool 12.60
License                         : Y3Rme25xaUoyQnQyaVZEa2d6fQ
Image Width                     : 1241
Image Height                    : 1157
Encoding Process                : Progressive DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1241x1157
Megapixels                      : 1.4
```

# Solution

There is a string that is very familiar to me in the license, which is a string that is encoded to base64 **Y3Rme25xaUoyQnQyaVZEa2d6fQ** if we decoded the string it will produce the flag

**ctf{nqiJ2Bt2iVDkgz}**
