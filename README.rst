==============
Broala::PE_XOR
==============

Bro plugin to detect and decrypt XOR-obfuscated Windows EXEs.

The key used to XOR the file will be automatically discovered and used
to XOR the file back to the original Window's executable.  Once the
file is deobfucated, it is passed back into the file analysis 
framework for further analysis.

Installation
============

From Source
-----------

.. code:: bash

   git clone https://github.com/broala/bro-xor-exe-plugin.git
   cd bro-xor-exe-plugin
   ./configure --bro-dist=$HOME/src/bro
   sudo make install

Now confirm that Bro can see it:

.. code:: bash

   bro -N | grep Broala

Usage
=====

Notices
-------

`Broala::XOR_Encrypted_PE_File_Seen` - This notice will be generated when an 
XOR'd Windows executable is discovered.  