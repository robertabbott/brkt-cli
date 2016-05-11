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


class Subcommand(object):
    """ brkt-cli subcommands need to implement this interface in order to
    be initialized.  Each subcommand module must have a function called
     get_subcommands() which returns a list of Subcommands.
    """
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def name(self):
        """ Return the subcommand name."""

    def exposed(self):
        """ Return True if this subcommand should be shown in the usage
        output of the top-level brkt command.
        """
        return True

    def init_logging(self, verbose):
        """ Subcommands can optionally implement this callback to initialize
        loggers.

        :param verbose: True if the user specified verbose logging
        """
        pass

    def verbose(self, values):
        """ Subcommands can optionally implement this callback to specify
        whether the verbose flag was specified.

        @param values the parsed arguments object
        """
        return False

    @abc.abstractmethod
    def register(self, subparsers):
        """ Add a subcommand to the top-level command parser.

        :param subparsers: the ArgumentParser object returned by
            add_subparsers()
        """
        pass

    @abc.abstractmethod
    def run(self, values):
        """ Run the subcommand.

        :return the exit status as an integer (0 means success)
        """
        pass
