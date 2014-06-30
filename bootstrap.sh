set -e

if [ ! -d config ];
then
	mkdir config;
fi

if [ ! -d m4 ];
then
	mkdir m4;
fi

aclocal && libtoolize --force && autoheader && \
automake --add-missing --copy && autoconf
