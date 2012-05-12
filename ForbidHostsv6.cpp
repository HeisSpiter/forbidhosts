/*
* ForbidHostsv6 - A tool for checking IPv6 SSH failed connections
* Copyright (C) 2012 Pierre Schweitzer <pierre@reactos.org
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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#ifdef WITH_INOTIFY
#include <sys/inotify.h>
#include <poll.h>
#endif
#include <fcntl.h>
#include <netdb.h>
#include <syslog.h>

#include <string>
#include <vector>
#include <ctime>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <csignal>

#define unreferenced_parameter(p) (void)p
#define unused_return(f) if (f) {}

const unsigned int MaxAttempts    = 5;
const unsigned int HostExpire     = 5;
const unsigned int FailurePenalty = 1;
const char * AuthLogFile          = "/var/log/auth.log";
const char * MailCommand          = "/usr/bin/mailx -s 'ForbidHostsv6 Report' "
                                    "root";
struct HostIPv6 {
    time_t       FirstSeen;
    std::string  Address;
    unsigned int Attempts;
    time_t       Expire;

    HostIPv6(time_t Date, const std::string & AuthAddress) {
        FirstSeen = Date;
        Address   = AuthAddress;
        Attempts  = 1;
        Expire    = Date + HostExpire * 60;
    }
};

struct Closer {
    bool operator() (const HostIPv6 & lhs, const HostIPv6 & rhs) const {
        return (lhs.Expire > rhs.Expire);
    }
};

static void SignalHandler(int Signal) {
    unreferenced_parameter(Signal);
    syslog(LOG_WARNING, "Deamon shutting down.");
    exit(EXIT_SUCCESS);
}

static bool IsValidLine(char * Line, char ** Address,
                        unsigned int * AddressLength) {
    char * SSHd;
    char * Method;
    char * User;
    char * Host;
    char * End;
    char * Colon;

    // Ensure we are dealing with SSH
    SSHd = strstr(Line, " sshd[");
    if (SSHd == 0) {
        return false;
    }

    // That the auth failed
    Method = strstr(Line, ": Failed ");
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
    Host += sizeof(" from ") - sizeof('\0');

    // With a port
    End = strstr(Host, " port ");
    if (End == 0) {
        return false;
    }

    // Finaly, ensure we have IPv6
    // Ignore any other IPs not to interfere with
    // other deamons
    Colon = strchr(Host, ':');
    if (Colon == 0 || Colon > End) {
        return false;
    }

    // Return host
    *Address = Host;
    *AddressLength = (End - Host);

    return true;
}

static void AddToDeny(std::string Host) {
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
    std::string Entry = "sshd: [" + Host + "]\n";
    unused_return(write(Deny, Entry.c_str(), Entry.length()));

    close(Deny);
    sync();

    // Look up the IP address
    struct sockaddr_in6 SockAddr;
    inet_pton(AF_INET6, Host.c_str(), &(SockAddr.sin6_addr));
    SockAddr.sin6_family = AF_INET6;

    char Name[NI_MAXHOST] = "";
    getnameinfo((struct sockaddr *)&SockAddr, sizeof(SockAddr),
                Name, NI_MAXHOST, NULL, 0, 0);

    // Send the mail
    FILE *Mailer = popen(MailCommand, "w");
    if (Mailer) {
        fprintf(Mailer, "Added the following hosts to /etc/hosts.deny:\n\n%s "
                        "(%s)\n\n--------------------------------------------"
                        "-------------------------", Host.c_str(), Name);
        pclose(Mailer);
    }

    // We are done here
    exit(EXIT_SUCCESS);
}

static bool UpdateHost(const std::string & Host,
                       std::vector<HostIPv6> & Hosts) {
    bool InsertRequired = true;

    for (std::vector<HostIPv6>::iterator it = Hosts.begin();
         it != Hosts.end(); ++it) {
        if ((*it).Address.compare(Host) == 0) {
            InsertRequired = false;

            if ((*it).Attempts >= MaxAttempts - 1) {
                // Max attempts
                // Add to hosts.deny
                AddToDeny((*it).Address);
                Hosts.erase(it);
            } else {
                // Update attempts count
                ++((*it).Attempts);
                (*it).Expire += (FailurePenalty * 60);
            }

            break;
        }
    }

    return InsertRequired;
}

static void ReadLine(int File, std::vector<HostIPv6> & Hosts) {
    char Line[255];
    char * Address;
    std::string Host;
    unsigned int Length, AddressLength;

    Length = read(File, Line, sizeof(Line));
    if (Length < 1) {
        return;
    }

    // Check line is valid
    if (!IsValidLine(Line, &Address, &AddressLength)) {
        return;
    }

    // Get the host
    Host = Address;
    Host.erase(AddressLength);

    if (UpdateHost(Host, Hosts)) {
        // Insert new host
        Hosts.push_back(HostIPv6(time(0), Host));
    }

    // In any case, resort list
    // An item can have been added, expire modified, or an item deleted
    sort(Hosts.begin(), Hosts.end(), Closer());
}

int main(int argc, char ** argv) {
    std::vector<HostIPv6> Hosts;

    unreferenced_parameter(argc);
    unreferenced_parameter(argv);

    // Install signals handler
    signal(SIGTERM, SignalHandler);
    signal(SIGINT, SignalHandler);
    signal(SIGQUIT, SignalHandler);

    syslog(LOG_INFO, "Daemon starting up");
    setlogmask(LOG_UPTO(LOG_INFO));
    openlog("ForbidHostsv6", LOG_CONS, LOG_USER);

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

    int AuthLog = open(AuthLogFile, O_RDONLY | O_NONBLOCK);
    if (AuthLog < 0) {
        exit(EXIT_FAILURE);
    }

    // Only take care of new entries
    lseek(AuthLog, 0, SEEK_END);

#ifdef WITH_INOTIFY
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
#endif

    for (;;) {
#ifdef WITH_INOTIFY
        struct pollfd FDs[] = {
            {iNotify, POLLIN, 0},
        };

        int Timeout = -1;
        // Set the poll timeout to the first
        // expired host to purge
        if (!Hosts.empty()) {
            Timeout = Hosts.back().Expire - time(0) * 1000;
        }

        int Event = poll(FDs, 1, Timeout);
        if (Event < 0) {
            break;
        } else if (Event > 0) {
            struct inotify_event iEvent;

            // Read the pending event
            // It will concern iAuth
            unused_return(read(iNotify, &iEvent, sizeof(struct inotify_event)));
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

#ifndef WITH_INOTIFY
        usleep(1000);
#endif
    }

#ifdef WITH_INOTIFY
    close(iAuth);
    close(iNotify);
#endif
    close(AuthLog);
    exit(EXIT_SUCCESS);
}
