import cmd
import enum
import logging
import logging.config
import os
import typing

import rich
import rich.prompt
import rich.table
from flatdict import FlatDict

from poochbotold import options
from poochbotold.options import OPTIONS

logger = logging.getLogger(__name__)

class Interpreter(cmd.Cmd):
    """
    Main interpreter for the PoochBot input loop. Houses the logic for 
    issuing prompts and accepting inputs for use elsewhere in the program.
    """

    prompt = " "

    def __init__(self, completekey: str = "tab", stdin=None, stdout=None) -> None:
        super().__init__(completekey, stdin, stdout)

    #region main loop

    def cmdloop(self, intro=None):
        """
        Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.
        """

        self.preloop()
        if self.use_rawinput and self.completekey:
            try:
                import readline

                self.old_completer = readline.get_completer()
                readline.set_completer(self.complete)
                readline.parse_and_bind(self.completekey + ": complete")
            except ImportError:
                pass
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro) + "\n")
            stop = None
            while not stop:
                if self.cmdqueue:
                    line = self.cmdqueue.pop(0)
                else:
                    if self.use_rawinput:
                        try:
                            # line = rich.prompt.Prompt.ask(self.prompt)
                            rich.print(self.prompt, end="", flush=True)
                            line = input(" ")
                            # line = input(self.prompt)
                        except EOFError:
                            line = "EOF"
                    else:
                        self.stdout.write(self.prompt)
                        self.stdout.flush()
                        line = self.stdin.readline()
                        if not len(line):
                            line = "EOF"
                        else:
                            line = line.rstrip("\r\n")
                line = self.precmd(line)
                stop = self.onecmd(line)
                stop = self.postcmd(stop, line)
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey:
                try:
                    import readline

                    readline.set_completer(self.old_completer)
                except ImportError:
                    pass

    #endregion

    #region help

    def do_help(self, arg: str):
        'List available commands with "help" or detailed help with "help cmd".'

        if arg:
            args = arg.split()

            if len(args) > 1:
                try:
                    getattr(self, "help_" + arg.replace(" ", "_"))()
                except AttributeError:
                    try:
                        doc: str = getattr(self, "_do_" + arg.replace(" ", "_")).__doc__
                        doc = doc.replace("    ", "").rstrip().lstrip()
                        if doc:
                            self.stdout.write("%s\n\n" % str(doc))
                            return
                    except AttributeError:
                        pass
            else:
                try:
                    getattr(self, "help_" + arg)()
                except AttributeError:
                    try:
                        doc: str = getattr(self, "do_" + arg).__doc__
                        doc = doc.replace("    ", "").rstrip().lstrip()
                        if doc:
                            self.stdout.write("\n%s\n" % str(doc))
                    except AttributeError:
                        pass
                print(
                    f"Usage: {arg} <{'|'.join(self._parse_subcommands(arg))}> [...]\n"
                )
        else:
            super().do_help(arg)

    #endregion

    #region defaults

    def emptyline(self) -> bool:
        """Return for an empty line"""
        
        return 0

    def default(self, line: str) -> None:
        """Return if unknown command"""
        
        logger.error("Unknown command.")
        return
    
    #endregion

    #region parsing

    def _parse_subcommands(self, command) -> list[str]:
        """Parse list of subcommands"""

        subcommands = []
        for func in dir(self):
            if f"_do_{command}_" in func:
                subcommands.append(func.split("_")[-1])
        return subcommands

    def _parse_params(self, params: str) -> tuple[str, list[str]]:
        """Parse list of parameters"""

        params = params.split(" ")
        arg = ""
        if params:
            arg = params.pop(0)
        return arg, params
    
    #endregion

    #region toplevel

    def _toplevel_subcommand(self, command_name: str, arg: str) -> None:
        """Runs the given subcommand of a main command"""

        if not arg:
            logger.error("You must specify a secondary command to run.")
            self.do_help(command_name)
            return
        
        arg, params = self._parse_params(arg)
        
        if arg in self._parse_subcommands(command_name):
            try:
                getattr(self, f"_do_{command_name}_{arg}")(*params)
            except TypeError:
                logger.exception("Incorrect arguments provided to command.")
                print("Help text:")
                self.do_help(f"{command_name} {arg}")
        else:
            self.do_help(command_name)

    #endregion

    #region options

    def do_options(self, arg: str) -> None:
        """Set options required for a modules to run."""

        self._toplevel_subcommand("options", arg)

    def _do_options_list(self) -> None:
        """Prints list of PoochBot options with their current values"""

        table = rich.table.Table("Name", "Type", "Value")
        name: str
        option: options.Option
        for name, option in dict(FlatDict(options.OPTIONS, delimiter=".")).items():
            table.add_row(
                name,
                option.type_.__name__,
                option.get_value_as_text(),
            )
        rich.print(table)

    def _do_options_set(self, option: str) -> None:
        """Sets an option to a given value using the given string format: `option=value`"""

        if "=" in option:
            key, value = option.split("=")
            if "," in value:
                value = value.split(",")

            try:
                option: options.Option = OPTIONS
                for sublevel in key.split("."):
                    option = option.get(sublevel)
            except:
                logger.error(f"Option does not exist.")
                return

            print(typing.get_origin(option.type_))
            try:
                if typing.get_origin(option.type_) == list:
                    if issubclass(typing.get_args(option.type_)[0], enum.Enum):
                        option.set_value(
                            [
                                getattr(typing.get_args(option.type_)[0], v)
                                for v in value
                            ]
                            if type(value) == list
                            else [getattr(typing.get_args(option.type_)[0], value)]
                        )
                    else:
                        option.set_value(value)
                elif issubclass(typing.get_args(option.type_), enum.Enum):
                    option.set_value(getattr(option.type_, value))
                else:
                    option.set_value(value)
            except ValueError:
                logger.exception(
                    f"Incorrect type of value. This option expects a {option.type_.__name__}."
                )
                return
            else:
                logger.info(
                    f"Set {option.name} to {option.get_value_as_text(expressive=True)}."
                )

    #endregion

    #region shell

    def do_shell(self, command: str) -> None:
        """Run something in the default shell. If PoochBot is running as root/Administrator, the command will do the same."""
        
        os.system(command)

    #endregion
