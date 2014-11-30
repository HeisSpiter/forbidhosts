/*
* ForbidHosts - A tool for checking IPv4 and IPv6 SSH failed connections
* Copyright (C) 2012 - 2014 Pierre Schweitzer <pierre@reactos.org>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "ForbidHosts.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifndef WITHOUT_INOTIFY
#include <sys/inotify.h>
#include <poll.h>
#endif
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>
#include <unistd.h>
#include <limits.h>

#include <string>
#include <vector>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <csignal>
#include <iostream>
#include <cstddef>

#define unreferenced_parameter(p) (void)p
#define unused_return(f) if (f) {}
#define soft_assert(e) if (!(e)) Assert(__FILE__, __LINE__, #e)
#define hard_assert(e) if (!(e)) Assert(__FILE__, __LINE__, #e, true)
#define MailCommandTpl "/usr/bin/mailx -s '%s - ForbidHosts Report' root"

const unsigned int MaxAttempts    = 5;
const time_t HostExpire           = 5;
const unsigned int FailurePenalty = 1;
const char * AuthLogDir           = "/var/log/";
const char * AuthLogFile          = "/var/log/auth.log";
const char * AuthFileName         = AuthLogFile + sizeof(AuthLogDir) / sizeof(AuthLogDir[0]) - 1;
char MailCommand[HOST_NAME_MAX + sizeof(MailCommandTpl) / sizeof(MailCommandTpl[0])];

struct HostIP {
    time_t            FirstSeen;
    std::string       Address;
    long unsigned int Attempts;
    time_t            Expire;
    bool              Written;

    HostIP(time_t Date, const std::string & AuthAddress) : Address(AuthAddress) {
        FirstSeen = Date;
        Attempts  = 1;
        Expire    = Date + HostExpire * 60;
        Written   = false;
    }
};

struct Closer {
    bool operator() (const HostIP & lhs, const HostIP & rhs) const {
        return (lhs.Expire > rhs.Expire);
    }
};

static void Assert(const char * File, unsigned int Line, const char * Assert,
                   bool Critical = false) {
    syslog((Critical ? LOG_CRIT : LOG_NOTICE),
           "Assertion '%s' failed at line %d in file %s", Assert, Line, File);

    if (Critical) {
        syslog(LOG_INFO, "Deamon shutting down.");
        exit(EXIT_FAILURE);
    }
}

static void SignalHandler(int Signal) {
    unreferenced_parameter(Signal);
    syslog(LOG_INFO, "Deamon shutting down.");
    exit(EXIT_SUCCESS);
}

static bool IsValidLine(char * Line, char ** Address,
                        size_t * AddressLength) {
    char * SSHd;
    char * Method;
    char * User;
    char * Host;
    char * End;
    char * Colon;
#ifdef WITH_IPV4
    char * Dot;
#endif

    // Ensure we are dealing with SSH
    SSHd = strstr(Line, " sshd[");
    if (SSHd == 0) {
        return false;
    }

    // That the auth failed
    Method = strstr(SSHd, ": Failed ");
    if (Method == 0) {
        return false;
    }
    Method += sizeof(": Failed ");

    // For an user
    User = strstr(Method, " for ");
    if (User == 0) {
        return false;
    }
    User += sizeof(" for ");

    // From an host
    Host = strstr(User, " from ");
    if (Host == 0) {
        return false;
    }
    // It is mandatory not to take \0 into account
    Host += sizeof(" from ") - sizeof(char);

    // With a port
    End = strstr(Host, " port ");
    if (End == 0) {
        return false;
    }

#ifdef WITH_IPV4
    // We might have either IPv4 or IPv6 here
    Colon = strchr(Host, ':');
    Dot = strchr(Host, '.');
    if ((Colon == 0 || Colon > End) &&
        (Dot == 0 || Dot > End)) {
        return false;
    }
#else
    // Finaly, ensure we have IPv6
    // Ignore any other IPs not to interfere with
    // other deamons
    Colon = strchr(Host, ':');
    if (Colon == 0 || Colon > End) {
        return false;
    }
#endif

    // Return host
    *Address = Host;
    *AddressLength = (End - Host);

    return true;
}

static long unsigned int IsLastRepeated(char * Line) {
    char * SSHd;
    char * Times;
    char * End;

    // Ensure we are dealing with SSH
    SSHd = strstr(Line, " sshd[");
    if (SSHd == 0) {
        return 0;
    }

    // That the message was repeated
    Times = strstr(SSHd, ": last message repeated ");
    if (Times == 0) {
        return 0;
    }
    // We want the exact number
    Times += sizeof(": last message repeated ") - sizeof(char);

    // Ensure the complete line is correct
    End = strstr(Times, " times");
    if (End == 0) {
        return 0;
    }

    return strtoul(Times, 0, 10);
}

static void AddToDeny(const std::string & Host) {
    std::string Entry;

    pid_t Child = fork();
    if (Child == -1 || Child > 0) {
        // Parent or failure, do nothing
        return;
    }

    // Now, open hosts.deny
    int Deny = open("/etc/hosts.deny", O_WRONLY | O_APPEND);
    if (Deny < 0) {
        exit(EXIT_FAILURE);
    }

    // Write the new entry
#ifdef WITH_IPV4
    // [] are only needed for IPv6
    bool IsIPv6 = (Host.find(':') != std::string::npos);
    if (IsIPv6) {
        Entry = "sshd: [" + Host + "]\n";
    } else {
        Entry = "sshd: " + Host + "\n";
    }
#else
    Entry = "sshd: [" + Host + "]\n";
#endif
    soft_assert(write(Deny, Entry.c_str(), Entry.length()) ==
                (ssize_t)Entry.length());

    close(Deny);
    sync();

#ifndef WITHOUT_EMAIL
    // Look up the IP address
    union {
#ifdef WITH_IPV4
        struct sockaddr_in in;
#endif
        struct sockaddr_in6 in6;
        struct sockaddr sa;
    } SockAddr;

#ifdef WITH_IPV4
    if (!IsIPv6) {
        inet_pton(AF_INET, Host.c_str(), &(SockAddr.in.sin_addr));
        SockAddr.in.sin_family = AF_INET;
    } else {
#endif
        inet_pton(AF_INET6, Host.c_str(), &(SockAddr.in6.sin6_addr));
        SockAddr.in6.sin6_family = AF_INET6;
#ifdef WITH_IPV4
    }
#endif

    char Name[NI_MAXHOST] = "";
    if (getnameinfo(&SockAddr.sa, sizeof(SockAddr), Name, NI_MAXHOST, NULL, 0, 0) != 0)
    {
        snprintf(Name, NI_MAXHOST, "%s", "Unknown");
    }

    // Send the mail
    FILE *Mailer = popen(MailCommand, "w");
    if (Mailer) {
        fprintf(Mailer, "Added the following hosts to /etc/hosts.deny:\n\n%s "
                        "(%s)\n\n--------------------------------------------"
                        "-------------------------", Host.c_str(), Name);
        pclose(Mailer);
    }
#endif

    // We are done here
    exit(EXIT_SUCCESS);
}

static bool UpdateHost(const std::string & Host,
                       std::vector<HostIP> & Hosts,
                       long unsigned int Repeated) {
    bool InsertRequired = true;

    soft_assert(!Host.empty());

    for (std::vector<HostIP>::iterator it = Hosts.begin();
         it != Hosts.end(); ++it) {
        if ((*it).Address.compare(Host) == 0) {
            InsertRequired = false;

            (*it).Attempts += Repeated;

            if ((*it).Attempts >= MaxAttempts && !(*it).Written) {
                // Max attempts
                // Add to hosts.deny
                AddToDeny((*it).Address);
                // Postpone a bit its expire so that it's still valid
                // if we have further events in log to process
                // It will get pruned later on when its expire date is gone
                (*it).Expire += 60;
                (*it).Written = true;
            } else {
                // Update expire
                (*it).Expire += (FailurePenalty * 60);
            }

            break;
        }
    }

    soft_assert((InsertRequired && Repeated == 1) || !InsertRequired);

    return InsertRequired;
}

static void ReadLine(int File, std::vector<HostIP> & Hosts) {
    char Line[255];
    char * Address;
    std::string Host;
    static std::string LastAddress = "";
    long unsigned int Repeated = 1;
    size_t AddressLength;
    ssize_t Length;

    for (;;) {
        unsigned int Read = 0;

        while (Read < sizeof(Line) / sizeof(char)) {
            Length = read(File, &Line[Read], sizeof(char));
            if (Length < 1) {
                // If read failed while nothing was read yet
                // there was nothing to read, break out
                if (Read == 0) {
                    return;
                // Otherwise, it is the end of the file
                } else {
                    break;
                }
            }

            // Ensure lines are read one by one
            if (Line[Read] == '\n') {
                Line[Read] = '\0';
                break;
            }

            // Increase buffer position
            Read++;
        }

        // Check if line is valid and if it is a repetition
        if (!IsValidLine(Line, &Address, &AddressLength)) {
            if (!LastAddress.empty()) {
                Repeated = IsLastRepeated(Line);
                if (Repeated == 0) {
                    LastAddress = "";
                    return;
                }
            } else {
                LastAddress = "";
                return;
            }
        } else {
            // Get the host
            Host = Address;
            Host.erase(AddressLength);

            // Save the host
            LastAddress = Host;
        }

        if (UpdateHost(LastAddress, Hosts, Repeated)) {
            // Insert new host
            Hosts.push_back(HostIP(time(0), Host));
        }

        // In any case, resort list
        // An item can have been added, expire modified, or an item deleted
        sort(Hosts.begin(), Hosts.end(), Closer());
    }
}

int main(int argc, char ** argv) {
    std::vector<HostIP> Hosts;
    struct sigaction SigHandling;

    unreferenced_parameter(argc);
    unreferenced_parameter(argv);

    memset(&SigHandling, 0, sizeof(struct sigaction));
    SigHandling.sa_handler = SignalHandler;

    // Install signals handler
    if (sigaction(SIGTERM, &SigHandling, NULL) < 0) {
        std::cerr << "Failed to install signal handler" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGINT, &SigHandling, NULL) < 0) {
        std::cerr << "Failed to install signal handler" << std::endl;
        exit(EXIT_FAILURE);
    }

    if (sigaction(SIGQUIT, &SigHandling, NULL) < 0) {
        std::cerr << "Failed to install signal handler" << std::endl;
        exit(EXIT_FAILURE);
    }

    // Prevent zombies
    SigHandling.sa_handler = NULL;
    SigHandling.sa_flags = SA_NOCLDWAIT;
    if (sigaction(SIGCHLD, &SigHandling, NULL) < 0) {
        std::cerr << "Failed to install signal handler" << std::endl;
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Daemon starting up");
    setlogmask(LOG_MASK(LOG_INFO) | LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_NOTICE));
    openlog("ForbidHosts", LOG_CONS, LOG_USER);

    // Start deamon
    pid_t Deamon = fork();
    if (Deamon < 0) {
        exit(EXIT_FAILURE);
    }

    if (Deamon > 0) {
        exit(EXIT_SUCCESS);
    }

    // Quit session
    umask(0);
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }

    // Go back to root
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    // Get rid of useless descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

#ifndef WITHOUT_EMAIL
    // Get our hostname
    {
        char HostName[HOST_NAME_MAX + 1];
        if (gethostname(HostName, sizeof(HostName)) < 0) {
            exit(EXIT_FAILURE);
        }

        sprintf(MailCommand, MailCommandTpl, HostName);
    }
#endif

    int AuthLog = open(AuthLogFile, O_RDONLY | O_NONBLOCK);
    if (AuthLog < 0) {
        exit(EXIT_FAILURE);
    }

    // Only take care of new entries
    lseek(AuthLog, 0, SEEK_END);

#ifndef WITHOUT_INOTIFY
    int iNotify = inotify_init1(IN_NONBLOCK);
    if (iNotify < 0) {
        close(AuthLog);
        exit(EXIT_FAILURE);
    }

    int iAuth = inotify_add_watch(iNotify, AuthLogFile, IN_MODIFY);
    if (iAuth < 0) {
        close(iNotify);
        close(AuthLog);
        exit(EXIT_FAILURE);
    }

    // Also watch log dir to spot new auth.log
    int iDir = inotify_add_watch(iNotify, AuthLogDir, IN_CREATE);
    if (iDir < 0) {
        inotify_rm_watch(iNotify, iAuth);
        close(iNotify);
        close(AuthLog);
        exit(EXIT_FAILURE);
    }
#endif

    for (;;) {
#ifndef WITHOUT_INOTIFY
        struct pollfd FDs[] = {
            {iNotify, POLLIN, 0},
        };

        int Timeout = -1;
        // Set the poll timeout to the first
        // expired host to purge
        if (!Hosts.empty()) {
            Timeout = (int)Hosts.back().Expire - (int)time(0) * 1000;
        }

        int Event = poll(FDs, 1, Timeout);
        if (Event < 0) {
            break;
        } else if (Event > 0) {
            // Make sure our iEvent is big enough for data & name
            struct {
                struct inotify_event Event;
                char Buffer[NAME_MAX + 1];
            } iEvent;

            // Read the pending event
            // It will concern iAuth
            soft_assert(read(iNotify, &iEvent, offsetof(struct inotify_event, name)) ==
                        offsetof(struct inotify_event, name));

            // If we have a name, read it
            if (iEvent.Event.len > 0) {
                soft_assert(read(iNotify, iEvent.Event.name, iEvent.Event.len) == iEvent.Event.len);
            }

            // Check the event
            if (iEvent.Event.mask & IN_CREATE) {
                // This happened in log dir
                soft_assert(iEvent.Event.wd == iDir);

                // Check we're dealing with our file
                if (strncmp(iEvent.Event.name, AuthFileName, iEvent.Event.len - 1) != 0) {
                    continue;
                }

                // Remove the file from watch list
                inotify_rm_watch(iNotify, iAuth);

                // Close file and restart
                soft_assert(close(AuthLog) == 0);

                AuthLog = open(AuthLogFile, O_RDONLY | O_NONBLOCK);
                if (AuthLog < 0) {
                    AuthLog = 0;
                    syslog(LOG_ERR, "Failed to reopen auth.log. Quitting.");
                    break;
                }

                // Only take care of new entries
                lseek(AuthLog, 0, SEEK_END);

                // Reinit watching
                iAuth = inotify_add_watch(iNotify, AuthLogFile,
                                          IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF);
                if (iAuth < 0) {
                    syslog(LOG_ERR, "Failed to rewatch auth.log. Quitting.");
                    break;
                }

                // Move back to watching
                continue;
            }
        }

        // Whatever happens, fall through
        // We have at least hosts to purge
#endif
        ReadLine(AuthLog, Hosts);

        // Purge queue of expired hosts
        while (!Hosts.empty()) {
            if (Hosts.back().Expire > time(0)) {
                break;
            }

            Hosts.pop_back();
        }

#ifndef WITHOUT_INOTIFY
        usleep(1000);
#endif
    }

#ifndef WITHOUT_INOTIFY
    inotify_rm_watch(iNotify, iDir);
    inotify_rm_watch(iNotify, iAuth);
    close(iNotify);
#endif
    close(AuthLog);
    exit(EXIT_SUCCESS);
}
