# Copyright 2015 Bracket Computing, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
# https://github.com/brkt/brkt-cli/blob/master/LICENSE
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and
# limitations under the License.
import abc


class ModuleInterface(object):
    """ brkt-cli modules need to implement this interface in order to
    be initialized.  Each module must have a function called get_interface()
    in its __init__.py which returns an instance of this interface.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def get_subcommands(self):
        """ Return the list of subcommands that are implemented by the module.
        @return a list of strings
        """
        pass

    @abc.abstractmethod
    def get_exposed_subcommands(self):
        """ Return the list of subcommands that are shown in brkt command
        usage.
        @return a list of strings
        """
        pass

    def init_logging(self, verbose):
        """ Modules can optionally implement this callback to initialize
        loggers.

        :param verbose: True if the user specified verbose logging
        """
        pass

    def verbose(self, subcommand, values):
        """ Modules can optionally implement this callback to specify
        whether the verbose flag was specified for the given subcommand.

        @param subcommand the subcommand to check
        @param values the parsed arguments object
        """
        return False

    @abc.abstractmethod
    def register_subcommand(self, subparsers, subcommand):
        """ Modules implement this callback in order to add subcommands to the
        command parser.

        :param subparsers: the ArgumentParser object returned by
            add_subparsers()
        :param subcommand: the subcommand name
        """
        pass

    @abc.abstractmethod
    def run_subcommand(self, subcommand, values):
        """ Modules implement this callback to run a subcommand.

        :return the exit status as an integer (0 means success)
        """
        pass
