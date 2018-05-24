==============================================================
libsparkcrypto - A cryptographic library implemented in SPARK.
==============================================================

libsparkcrypto is a formally verified implementation of several widely used
symmetric cryptographic algorithms using the SPARK programming language and
toolset [1]_.  For the complete library proofs of the absence of run-time
errors like type range violations, division by zero and numerical overflows are
available. Some of its subprograms include proofs of partial correctness.

The distribution contains test cases for all implemented algorithms and a
benchmark to compare its performance with the OpenSSL library [2]_. The
achieved speed has been found to be very close to the optimized C and Assembler
implementations of OpenSSL.

Copyright, Warranty and Licensing
=================================

| Copyright (C) 2010, Alexander Senier
| Copyright (C) 2010, secunet Security Networks AG

| All rights reserved.

libsparkcrypto is released under the simplified BSD license::

   Redistribution  and  use  in  source  and  binary  forms,  with  or  without
   modification, are permitted provided that the following conditions are met:

      * Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.

      * Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

      * Neither the name of the  nor the names of its contributors may be used
        to endorse or promote products derived from this software without
        specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE  COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY  EXPRESS OR IMPLIED WARRANTIES,  INCLUDING, BUT NOT LIMITED  TO, THE
   IMPLIED WARRANTIES OF  MERCHANTABILITY AND FITNESS FOR  A PARTICULAR PURPOSE
   ARE  DISCLAIMED. IN  NO EVENT  SHALL  THE COPYRIGHT  HOLDER OR  CONTRIBUTORS
   BE  LIABLE FOR  ANY  DIRECT, INDIRECT,  INCIDENTAL,  SPECIAL, EXEMPLARY,  OR
   CONSEQUENTIAL  DAMAGES  (INCLUDING,  BUT  NOT  LIMITED  TO,  PROCUREMENT  OF
   SUBSTITUTE GOODS  OR SERVICES; LOSS  OF USE,  DATA, OR PROFITS;  OR BUSINESS
   INTERRUPTION)  HOWEVER CAUSED  AND ON  ANY THEORY  OF LIABILITY,  WHETHER IN
   CONTRACT,  STRICT LIABILITY,  OR  TORT (INCLUDING  NEGLIGENCE OR  OTHERWISE)
   ARISING IN ANY WAY  OUT OF THE USE OF THIS SOFTWARE, EVEN  IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.

Features
========

Version 0.1.1 of libsparkcrypto implements the following symmetric cryptographic
algorithms and modes:

- AES-128, AES-192, AES-256
- AES-CBC (all supported AES modes)
- SHA-256, SHA-384, SHA-512
- HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
- PRF-HMAC-SHA-256, PRF-HMAC-SHA-384, PRF-HMAC-SHA-512
- RIPEMD-160
- HMAC-RIPEMD-160

The list of changes in libsparkcrypto is available in the CHANGES_ file and the
list of planned enhancements in the TODO_ file.

Download
========

Release version
---------------

The current release version of libsparkcrypto is available at
http://senier.net/libsparkcrypto/libsparkcrypto-0.1.1.tgz

An API documentation of the current release version can be found at
http://senier.net/libsparkcrypto/lsc.html

Development version
-------------------

The current development version of libsparkcrypto is available through its GIT
[3]_ repository: ``http://git.codelabs.ch/git/spark-crypto.git``

A browsable version of the repository is also available here:
http://git.codelabs.ch/?p=spark-crypto.git

Building and installing
=======================

Required tools
--------------

To build and prove libsparkcrypto, the following tools are required:

- GCC or GNAT Pro
- SPARK 9 (SPARK Pro or SPARK GPL)
- GNU make, version >= 3.81
- OpenSSL (for building the benchmark, tested with 0.9.8g)
- AdaBrowse (for building the API documentation, tested with 4.0.3)
- Docutils (for building the documentation, tested with 0.6)
- SPARKUnit [4]_ (for unit testing, tested with 0.1.0)

The primary development environments of libsparkcrypto are Debian 5 (x86_64)
and Ubuntu 10.04 (x86_64). Though the source and project files should be system
independent, the Makefiles assume a UNIXish system (cygwin seems to work).
Tools like ``mkdir``, ``uname``, ``tail`` and ``install`` must be present in
the systems search path.

Build process
-------------

To build libsparkcrypto, change to the source directory and type::

$ make

You can install the library to <destination>, by typing::

$ make DESTDIR=<destination> install

Supported systems
-----------------

libsparkcrypto was successfully built and tested on the following systems:

+------------------+--------------+-----------------------------------------------+
|operating system  | architecture |  toolchain                                    |
+==================+==============+===============================================+
|Ubuntu 10.04      | x86_64       |  GNAT-GPL 2010 or GCC-4.4.3, SPARK-GPL/-Pro 9 |
+------------------+--------------+-----------------------------------------------+
|Debian 5          | i686         |  GCC-4.3.2, SPARK-GPL 9                       |
+------------------+--------------+-----------------------------------------------+
|Debian 5          | x86_64       |  GNAT-Pro 6.3.1 or GCC-4.3.2, SPARK-Pro 9     |
+------------------+--------------+-----------------------------------------------+

If you were able to build and verify libsparkcrypto on a platform not listed
here, please send mail to Alexander Senier <mail@senier.net> for inclusion into
that list. Please provide information about type and version of your operation
system, the toolchain and the CPU architecture. We would also appreciate your
proof summary and the results of the ``benchmark`` tool (if providing that,
please also tell us the version of your OpenSSL library).

Known issues
------------

- GNAT Pro 6.3.1 (and maybe other versions) is known to cause trouble if
  optimization is set to -O3. It will generate invalid code for all  HMAC
  implementations, all respective test cases will fail.

Please send bug reports and comments to Alexander Senier <mail@senier.net>.

Using libsparkcrypto
====================

Examples for using libsparkcrypto can be found in the ``tests`` subdirectory.

A user of the library has to provide a shadow for the package ``Interfaces``
providing a type definition for at least ``Unsigned_8``, ``Unsigned_32`` and
``Unsigned_64``.

Extending libsparkcrypto
========================

You are welcome to extend libsparkcrypto according to the terms of the
simplified BSD license referenced above. Please obey the following rules when
contributing changes back to the project:

- Make sure no undischarged VCs remain.
- Make sure the code compiles in both modes MODE=release and MODE=debug.
- Provide reference to documents and test cases for the parts you implemented.
- Make sure you successfully ran the test suite (``make test``).
- Try to stay consistent with the current style of the source.
- If feasible, implement a benchmark for your code.
- Create your patches using git-format-patch.

The Directory structure of libsparkcrypto is as follows:

+---------------+-------------------------------------------------------------+
|directory      | content                                                     |
+===============+=============================================================+
|``src/shared`` | sources analyzed by SPARK Examiner and used by Ada compiler |
+---------------+-------------------------------------------------------------+
|``src/spark``  | sources only analyzed by SPARK Examiner                     |
+---------------+-------------------------------------------------------------+
|``src/ada``    | sources only used by Ada compiler                           |
+---------------+-------------------------------------------------------------+

The directories ``src/ada`` and ``src/shared`` have a sub-directory ``generic``,
which contains platform independent code. Furthermore, there are
feature-specific directories like ``little_endian`` and architecture-specific
directories like ``x86_64`` which are included to proof and build steps as
configured.

Configuration is performed automatically by the top-level ``Makefile`` and can be
altered by passing the following variables to ``make``:

+------------------+----------------------------------------------------------------------+
|variable          | description                                                          |
+==================+======================================================================+
|``ARCH``          | CPU architecture as reported by ``uname -m``.                        |
+------------------+----------------------------------------------------------------------+
|``MODE``          | Build mode (``release`` or ``debug``).                               |
+------------------+----------------------------------------------------------------------+
|``OPT``           | Optimization level to use (``s``, ``0``, ``1``, ``2`` or ``3``).     |
+------------------+----------------------------------------------------------------------+
|``RUNTIME``       | Runtime to build for (``native`` or ``zfp``).                        |
+------------------+----------------------------------------------------------------------+
|``NO_TESTS``      | Disable tests step.                                                  |
+------------------+----------------------------------------------------------------------+
|``NO_SPARK``      | Disable SPARK proof step.                                            |
+------------------+----------------------------------------------------------------------+
|``NO_ISABELLE``   | Disable ISABELLE proof step.                                         |
+------------------+----------------------------------------------------------------------+
|``NO_APIDOC``     | Disable generation of API documentation.                             |
+------------------+----------------------------------------------------------------------+
|``TARGET_CFG``    | Target system configuration.                                         |
+------------------+----------------------------------------------------------------------+
|``SPARK_DIR``     | Base directory of the SPARK installation.                            |
+------------------+----------------------------------------------------------------------+
|``SPARKUNIT_DIR`` | Base directory of the SPARKUnit installation.                        |
+------------------+----------------------------------------------------------------------+
|``DESTDIR``       | Installation base directory.                                         |
+------------------+----------------------------------------------------------------------+

Credits
=======

- Thanks to Adrian-Ken Rüegsegger and Reto Buerki for hosting the project's GIT
  repository.

- Thanks to Adacore and Altran Praxis for review, comments and support with
  many tricky problems.



.. [1] SPARK - http://www.altran-praxis.com/spark.aspx
.. [2] OpenSSL: The Open Source toolkit for SSL/TLS - http://www.openssl.org
.. [3] GIT - the fast version control system, http://git-scm.com
.. [4] SPARKUnit - A unit test framework for the SPARK programming language, http://senier.net/SPARKUnit
.. _CHANGES: CHANGES.html
.. _TODO: TODO.html