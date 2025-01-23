.. SPDX-License-Identifier: GPL-2.0-only

README Intro
--------------------

mmc-utils is a tool for configuring MMC storage devices from userspace.


Source
------

mmc-utils resides in a git repo, the canonical place is:

https://git.kernel.org/pub/scm/utils/mmc/mmc-utils.git


Mailing list
------------

The project uses the kernel's mmc mailing list.  There you should submit your
patches, ask for help, or discuss mmc-utils related issues. A patch should be
sent as a mail to the linux-mmc@vger.kernel.org mailing list with maintainers
as Cc recipients.  Archives can be found here:

    https://www.spinics.net/lists/linux-mmc/

or here:

    https://lore.kernel.org/linux-mmc/


Author
------

mmc-utils was written by Chris Ball <cjb@laptop.org> and <chris@printf.net>.


Maintainers
-----------

Avri Altman <avri.altman@wdc.com>
Ulf Hansson <ulf.hansson@linaro.org>


Building
--------

Just type::

 $ make
 $ make install

Note that GNU make is required.  Make install also builds the man page

To cross-compile mmc-utils you can use environment variables. e.g. to build
statically linked for ARM64::

 $ make clean
 $ CC=aarch64-linux-gnu-gcc CFLAGS=' -g -O2 -static' make


Documentation
-------------

mmc-utils uses Sphinx_ to generate documentation from the reStructuredText_ files.
To build HTML formatted documentation run ``make html-docs`` and direct your
browser to :file:`./docs/_build/html/index.html`.

.. _reStructuredText: https://www.sphinx-doc.org/rest.html
.. _Sphinx: https://www.sphinx-doc.org


License
-------

This project is licensed under GPL-2.0-only.
