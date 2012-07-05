#!/usr/bin/env python

import argparse
import json
import logging
import os
import pprint
import socket
import sys
import traceback

DEFAULT_ROOT = "/opt/tr/etc"

class SystemConfig(object):
    def __init__(self, syshosts, sysgroups, sysversions):
        self.syshosts = syshosts
        self.sysgroups = sysgroups
        self.sysversions = sysversions

        self.config = self._build_config()
        #pprint.pprint(self.config)

    
    def _build_config(self):
        """ Build single config from syshosts, sysgroups, and sysversions with the following format:
            
            {u'localdev': {'envs': {u'localdev': {'groups': {u'all': {'packages': {}},
                                                             u'web': {'packages': {u'apache': {'release': u'0',
                                                                                               'version': u'0'},
                                                                                   u'techresidents_web': {'release': u'1',
                                                                                                          'version': u'0.3'}}}},
                                                  'packages': {u'apache': {'release': u'0',
                                                                           'version': u'0'},
                                                               u'techresidents_web': {'release': u'1',
                                                                                      'version': u'0.3'}}}}}}
        """

        config = {}

        for syshost, syshost_config in self.syshosts.items():
            config[syshost] = {}
            config[syshost]["envs"] = {}

            syshost_groups = syshost_config["groups"]

            for env in syshost_config["envs"]:
                config[syshost]["envs"][env] = {}
                config[syshost]["envs"][env]["groups"] = {}
                config[syshost]["envs"][env]["packages"] = {}

            for group in syshost_config["groups"]:
                for env in syshost_config["envs"]:
                    

                    config[syshost]["envs"][env]["groups"][group] = {
                                "packages": {}
                            }

                    if group in self.sysgroups:
                        for package in self.sysgroups[group]["packages"]:

                            version, release = self._package_version(package, env, syshost_groups)

                            config[syshost]["envs"][env]["groups"][group]["packages"][package] = {
                                    "version": version,
                                    "release": release
                                    }


                            config[syshost]["envs"][env]["packages"][package] = {
                                    "version": version,
                                    "release": release
                                    }
        return config


    def _package_version(self, package, env, groups):

        def version_release_key(version_release):
            version = version_release[0]
            release = version_release[1]

            version_items = version.replace("-SNAPSHOT", "").split(".")

            while len(version_items) < 3:
                version_items.append(0)

            return reduce(lambda x,y: int(x)*1000 + int(y), version_items)


        version_releases = []
        if package in self.sysversions:
            if env in self.sysversions[package]["envs"]:
                version_groups = self.sysversions[package]["envs"][env]["groups"]
                for group in version_groups:
                    if group in groups:
                        version_releases.append((version_groups[group]["version"], version_groups[group]["release"]))
        

        if len(version_releases) > 1:
            version_releases.sort(key=version_release_key, reverse=True)

        return version_releases[0]


    def groups(self, host_filter=None, env_filter=None, group_filter=None):
        for host, host_item in self.config.items():
            if host_filter and not host_filter(host):
                continue

            for env, env_item in host_item["envs"].items():
                if env_filter and not env_filter(env):
                    continue

                for group, group_item in env_item["groups"].items():
                    if group_filter and not group_filter(group):
                        continue

                    yield {
                            "host": host,
                            "env": env,
                            "group": group
                            }
    

    def packages(self, host_filter=None, env_filter=None, group_filter=None, package_filter=None):
        for host, host_item in self.config.items():
            if host_filter and not host_filter(host):
                continue

            for env, env_item in host_item["envs"].items():
                if env_filter and not env_filter(env):
                    continue

                for group, group_item in env_item["groups"].items():
                    if group_filter and not group_filter(group):
                        continue

                    for package, package_item in group_item["packages"].items():
                        if package_filter and not package_filter(package):
                            continue

                        yield {
                                "host": host,
                                "env": env,
                                "group": group,
                                "package": package,
                                "version": package_item["version"],
                                "release": package_item["release"]
                                }


#Filters
def list_filter(items=None):
    items = items or []
    def filter(item):
        if items:
            return item in items
        else:
            return True
    return filter

def localhost_filter(additional_hosts=None):
    hosts = list(additional_hosts or [])
    hosts.append(socket.gethostname())

    hostname, aliases, ip_addresses = socket.gethostbyname_ex(socket.gethostname())
    hosts.append(hostname)
    hosts.extend(aliases)
    hosts.extend(ip_addresses)

    for alias in aliases:
        hostname, aliases, ip_addresses = socket.gethostbyname_ex(alias)
        hosts.append(hostname)
        hosts.extend(aliases)
        hosts.extend(ip_addresses)
    
    hosts = set(hosts)

    def filter(host):
        return host in hosts
    
    return filter



#Command Handlers

def groupsCommandHandler(sysconfig, args):
    """
    """
    log = logging.getLogger("groupsCommandHandler")

    groups = sysconfig.groups(
            host_filter = localhost_filter(args.hosts) if "localhost" in (args.hosts or []) else list_filter(args.hosts),
            env_filter = list_filter(args.environments),
            group_filter = list_filter(args.groups))

    for group in groups:
        log.info(args.format.format(**group).replace("\\n", "\n"))


groupsCommandHandler.examples = """Examples:
    sysutil.py groups             #List system groups
"""

def packagesCommandHandler(sysconfig, args):
    """
    """
    log = logging.getLogger("packagesCommandHandler")

    packages = sysconfig.packages(
            host_filter = localhost_filter(args.hosts) if "localhost" in (args.hosts or []) else list_filter(args.hosts),
            env_filter = list_filter(args.environments),
            group_filter = list_filter(args.groups),
            package_filter = list_filter(args.packages))

    for package in packages:
        log.info(args.format.format(**package).replace("\\n", "\n"))


packagesCommandHandler.examples = """Examples:
    sysutil.py packages             #List system packages
"""


def main(argv):

    def parse_arguments():
        parser = argparse.ArgumentParser(description="sysutil.py is a helper for working with tech residents system files.")
        parser.add_argument("-r", "--root", default=DEFAULT_ROOT, help="root directory containing syshosts, sysgroups, and sysversion files")

        commandParsers = parser.add_subparsers()
        
        #groups parser
        groupsCommandParser = commandParsers.add_parser(
                "groups",
                help="list system groups",
                description=groupsCommandHandler.__doc__,
                epilog=groupsCommandHandler.examples,
                formatter_class=argparse.RawDescriptionHelpFormatter
                )
        groupsCommandParser.set_defaults(command="groups", commandHandler=groupsCommandHandler)
        groupsCommandParser.add_argument("-H", "--hosts", nargs="+", help="hosts filter")
        groupsCommandParser.add_argument("-e", "--environments", nargs="+", help="environments filter")
        groupsCommandParser.add_argument("-g", "--groups", nargs="+", help="groups filter")
        groupsCommandParser.add_argument("-f", "--format", default="{host} {env} {group}", help="format string")

        #packages parser
        packagesCommandParser = commandParsers.add_parser(
                "packages",
                help="list system packages",
                description=packagesCommandHandler.__doc__,
                epilog=packagesCommandHandler.examples,
                formatter_class=argparse.RawDescriptionHelpFormatter
                )
        packagesCommandParser.set_defaults(command="packages", commandHandler=packagesCommandHandler)
        packagesCommandParser.add_argument("-H", "--hosts", nargs="+", help="hosts filter")
        packagesCommandParser.add_argument("-e", "--environments", nargs="+", help="environments filter")
        packagesCommandParser.add_argument("-g", "--groups", nargs="+", help="groups filter")
        packagesCommandParser.add_argument("-p", "--packages", nargs="+", help="packages filter")
        packagesCommandParser.add_argument("-f", "--format", default="{host} {env} {group} {package} {version} {release}", help="format string")

        return parser.parse_args(argv[1:])


    #configure logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setLevel(logging.INFO)
    logger.addHandler(consoleHandler)
    
    log = logging.getLogger("main")

    args = parse_arguments()

    try:
        syshosts = json.loads(open(os.path.join(args.root, "syshosts")).read())
        sysgroups = json.loads(open(os.path.join(args.root, "sysgroups")).read())
        sysversions = json.loads(open(os.path.join(args.root, "sysversions")).read())

        sysconfig = SystemConfig(syshosts, sysgroups, sysversions)

        #Invoke command handler
        args.commandHandler(sysconfig, args)

        return 0
    
    except KeyboardInterrupt:
        return 1
    
    except Exception as error:
        log.error("Unhandled exception: %s" % str(error))
        log.error(traceback.format_exc())
        return 2

if __name__ == '__main__':
    sys.exit(main(sys.argv))
    
