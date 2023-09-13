# Static library

To build for USB Armory MK II, issue:

```
mkdir build
cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=../toolchain/usbarmory-mkii.cmake
make
```

Output will be `libplugntrust.a`.
