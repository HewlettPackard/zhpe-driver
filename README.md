Support for the linux zhpe bridge device driver
-----------------------------------------------------

# 1. Install dependencies
	$ sudo -i apt-get install build-essential linux-headers-$(uname -r) cmake valgrind libudev-dev git wget flex
	$ sudo -i apt-get build-dep openmpi libtool
	$ sudo -i apt-get install librdmacm-dev # optional: not needed if OFED installed or verbs not required
    
# 2. Install libtool from source
	$ wget http://ftpmirror.gnu.org/libtool/libtool-2.4.6.tar.gz
	$ tar -xzf libtool-2.4.6.tar.gz
	$ cd libtool-2.4.6
	$ ./configure
	$ make	
	$ sudo make install
Make sure the new version of libtoolize is first in your PATH.
   
# Building the driver and helper (using DKMS or manually)

## DKMS method

This method has several advantages; it will manage building and installing the driver for multiple kernel versions, it automatically supplies driver parameters when the driver is loaded and handles all the driver build steps.

### 1. Install DKMS package
	$ sudo -i apt-get install dkms

### 2. Clone zhpe-support into ${SRC_DIR}
	$ cd ${SRC_DIR}
	$ git clone https://github.hpe.com/zhpe-support.git

### 3. Register zhpe-support with DKMS (note driver version for build/install commands)
	$ sudo -i dkms add ${PWD}/zhpe-support

### 4. Build and install driver
	$ sudo -i dkms build zhpe/<driver_version> -k <kernel_version>
	$ sudo -i dkms install zhpe/<driver_version> -k <kernel_version>

### 5. Load driver into kernel
	$ sudo -i modprobe zhpe

### 6. Unload driver and uninstall
	$ sudo -i modprobe -r zhpe
	$ sudo -i dkms uninstall zhpe/<driver_version> -k <kernel_version>

### 7. Remove driver from DKMS
	$ sudo -i dkms remove zhpe/<driver_version> -k <kernel_version>

## Manual method (build into ${TEST_DIR})

NOTE: Builds in the zhpe-support tree currently install automatically into ${TEST_DIR}. This is not true for zhpe-libfabric and zhpe-ompi.

### 1. Clone zhpe-support into ${SRC_DIR}
	$ cd ${SRC_DIR}
	$ git clone https://github.com/HewlettPackard/zhpe-support.git

### 2. Generate makefiles and build and load driver.
	$ cd ${SRC_DIR}/zhpe-support
	$ make
	$ sudo -i insmod ${TEST_DIR}/lib/modules/zhpe.ko
