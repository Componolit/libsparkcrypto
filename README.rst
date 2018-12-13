===================================================================
libsparkcrypto - A cryptographic library implemented in SPARK 2014.
===================================================================

libsparkcrypto is a formally verified implementation of several widely used
cryptographic algorithms using the SPARK 2014 programming language and toolset
[1]_.  For the complete library proofs of the absence of run-time errors like
type range violations, division by zero and numerical overflows are available.
Some of its subprograms include proofs of partial correctness.

The distribution contains test cases for all implemented algorithms and a
benchmark to compare its performance with the OpenSSL library [2]_.

Copyright, Warranty and Licensing
=================================

| Copyright (C) 2011-2017  Stefan Berghofer
| Copyright (C) 2010-2011,2018  Alexander Senier
| Copyright (C) 2010-2017  secunet Security Networks AG

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

This version of libsparkcrypto implements the following cryptographic
algorithms and modes:

- AES-128, AES-192, AES-256
- AES-CBC (all supported AES modes)
- SHA-1
- HMAC-SHA1
- SHA-256, SHA-384, SHA-512
- HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512
- PRF-HMAC-SHA-256, PRF-HMAC-SHA-384, PRF-HMAC-SHA-512
- RIPEMD-160
- HMAC-RIPEMD-160
- ECDSA, ECGDSA

Development version
===================

The current development version of libsparkcrypto is available through its GIT
[3]_ repository: ``https://github.com/Componolit/libsparkcrypto.git``

A browsable version of the repository is also available here:
https://github.com/Componolit/libsparkcrypto

Building and installing
=======================

Required tools
--------------

To build and prove libsparkcrypto, the following tools are required:

- GNAT (recent Pro or FSF)
- SPARK 2014 (tested with Pro 19.0 and Community 2018)
- GNU make
- OpenSSL (for building the benchmark, tested with 1.1.1j)
- SPARKUnit [4]_ (for unit testing, tested with 0.1.0)

The primary development environments of libsparkcrypto are Debian (x86_64) and
Ubuntu (x86_64). Though the source and project files should be system
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
|Debian 9          | x86_64       |  SPARK Pro 19.0, GNAT Pro 19.0                |
+------------------+--------------+-----------------------------------------------+
|Debian 9          | x86_64       |  GNAT Community 2018                          |
+------------------+--------------+-----------------------------------------------+

Please send bug reports and comments to Alexander Senier <senier@componolit.com>.

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
- Create a pull request on GitHub

The Directory structure of libsparkcrypto is as follows:

+---------------+----------------------------------------------------+
|directory      | content                                            |
+===============+====================================================+
|``src/shared`` | sources analyzed by SPARK and used by Ada compiler |
+---------------+----------------------------------------------------+
|``src/spark``  | sources only analyzed by SPARK                     |
+---------------+----------------------------------------------------+
|``src/ada``    | sources only used by Ada compiler                  |
+---------------+----------------------------------------------------+

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
|``SHARED``        | Build a shared library (``0``, ``1``).                               |
+------------------+----------------------------------------------------------------------+
|``RUNTIME``       | Runtime to build for (``native`` or ``zfp``).                        |
+------------------+----------------------------------------------------------------------+
|``NO_TESTS``      | Disable tests step.                                                  |
+------------------+----------------------------------------------------------------------+
|``NO_SPARK``      | Disable SPARK proof step.                                            |
+------------------+----------------------------------------------------------------------+
|``NO_ISABELLE``   | Disable ISABELLE proof step.                                         |
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


.. [1] SPARK 2014 - https://www.adacore.com/about-spark
.. [2] OpenSSL: The Open Source toolkit for SSL/TLS - http://www.openssl.org
.. [3] GIT - the fast version control system, http://git-scm.com
.. [4] SPARKUnit - A unit test framework for the SPARK programming language, http://senier.net/SPARKUnit
