#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ForbidHosts], [1.0], [pierre@reactos.org])
AC_CONFIG_SRCDIR([ForbidHosts.cpp])
AC_CONFIG_HEADERS([ForbidHosts.h])
AM_INIT_AUTOMAKE

AC_REQUIRE_CPP

# Checks for programs.
AC_PROG_CPP
AM_PROG_CC_C_O

AC_LANG([C++])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h sys/socket.h syslog.h])

AC_ARG_ENABLE(inotify, [  --disable-inotify  Disable inotify use.], [],[enableval=yes])
if test "z$enableval" = zno ; then
    enable_inotify="no"
else
    enable_inotify="no"
    AC_CHECK_HEADERS(poll.h, enable_inotify="yes",)
    AC_CHECK_HEADERS(sys/inotify.h, enable_inotify="yes",)
fi
if test $enable_inotify = "no" ; then
    AC_DEFINE([WITHOUT_INOTIFY], 1, [Define if you want to disable the inotify use])
fi
AM_CONDITIONAL(WITHOUT_INOTIFY, test $enable_inotify != "yes")

AC_ARG_ENABLE(email, [  --disable-email  Disable email sending.], [],[enableval=yes])
if test "z$enableval" = zno ; then
    enable_email="no"
else
    enable_email="yes"
fi
if test $enable_email = "no" ; then
    AC_DEFINE([WITHOUT_EMAIL], 1, [Define if you want to disable the email sending])
fi
AM_CONDITIONAL(WITHOUT_EMAIL, test $enable_email != "yes")

AC_ARG_ENABLE(ipv4, [  --enable-ipv4  Enable the IPv4 support.], [],[enableval=no])
if test "z$enableval" = zyes ; then
    enable_ipv4="yes"
else
    enable_ipv4="no"
fi
if test $enable_ipv4 = "yes" ; then
    AC_DEFINE([WITH_IPV4], 1, [Define if you want to enable the IPv4 support])
fi
AM_CONDITIONAL(WITH_IPV4, test $enable_ipv4 != "no")

# Check for functions
AC_CHECK_FUNCS([strstr strchr])

# Checks for typedefs, structures, and compiler characteristics.
AC_FUNC_FORK
AC_HEADER_STDBOOL
AC_PROG_CXX
AC_TYPE_PID_T

AC_CONFIG_FILES([makefile])
AC_OUTPUT
