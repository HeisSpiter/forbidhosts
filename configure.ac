#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([ForbidHosts], [1.8], [pierre@reactos.org])
AC_CONFIG_SRCDIR([ForbidHosts.cpp])
AC_CONFIG_HEADERS([ForbidHosts.h])
AM_INIT_AUTOMAKE

AC_REQUIRE_CPP

# Checks for programs.
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AM_PROG_CC_C_O
AC_PROG_LN_S
AC_PROG_RANLIB

AC_LANG([C++])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h sys/socket.h syslog.h limits.h unistd.h])

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
AS_IF([test "z$enableval" = zno], [enable_email="no"], [enable_email="yes"])
if test $enable_email = "no" ; then
    AC_DEFINE([WITHOUT_EMAIL], 1, [Define if you want to disable the email sending])
fi
AM_CONDITIONAL(WITHOUT_EMAIL, test $enable_email != "yes")

AC_ARG_ENABLE(ipv4, [  --enable-ipv4  Enable the IPv4 support.], [],[enableval=no])
AS_IF([test "z$enableval" = zyes], [enable_ipv4="yes"], [enable_ipv4="no"])
if test $enable_ipv4 = "yes" ; then
    AC_DEFINE([WITH_IPV4], 1, [Define if you want to enable the IPv4 support])
fi
AM_CONDITIONAL(WITH_IPV4, test $enable_ipv4 != "no")

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([strstr strchr gethostname memset strtoul])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Get configuration
AC_ARG_VAR([AUTHLOG_FILE], [Path where to find auth.log file.
                            Default = "/var/log/auth.log"])
AS_IF([test "z$AUTHLOG_FILE" = z], [AUTHLOG_FILE="/var/log/auth.log"])
AC_DEFINE_UNQUOTED([AUTHLOG_FILE], ["$AUTHLOG_FILE"], [Define to the path of the auth.log file])

AC_ARG_VAR([DENY_FILE], [Path where to find hosts.deny file.
                         Default = "/etc/hosts.deny"])
AS_IF([test "z$DENY_FILE" = z], [DENY_FILE="/etc/hosts.deny"])
AC_DEFINE_UNQUOTED([DENY_FILE], ["$DENY_FILE"], [Define to the path of the hosts.deny file])

AC_CONFIG_FILES([makefile])
AC_OUTPUT

echo
echo ForbidHosts AC_PACKAGE_VERSION configured
echo
echo "inotify:	$enable_inotify"
echo "email: 		$enable_email"
echo "IPv4:		$enable_ipv4"
echo "log file:	$AUTHLOG_FILE"
echo "deny file:	$DENY_FILE"
echo
echo "Environment configured. You can now run \"$ac_make\" to build ForbidHosts"
