================
 Broala::PE_XOR
================

Bro plugin to detect and decrypt XOR-encrypted EXEs.

==============
 Installation
==============


 From Source
=============

.. 
   git clone https://github.com/broala/bro-xor-exe-plugin.git
   cd bro-xor-exe-plugin
   ./configure --bro-dist=$HOME/src/bro
   sudo make install

Now confirm that Bro can see it:

.. 
   bro -N | grep broala


From Plugin Package
===================

.. 
   cd /usr/local/bro/lib/bro/plugins
   tar xvzf ~/src/Broala_PE_XOR-0.1.tar.gz

Now confirm that Bro can see it:

.. 
   bro -N | grep broala

