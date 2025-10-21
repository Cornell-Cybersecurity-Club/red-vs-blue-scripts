import cmd
import logging
import logging.config

import rich
import rich.prompt
import rich.table

from poochbot.utils import ExitException
from poochbot.options import OPTIONS

logger = logging.getLogger(__name__)

class Interpreter(cmd.Cmd):
    """
    Main interpreter for the PoochBot input loop. Houses the logic for 
    issuing prompts and accepting inputs for use elsewhere in the program.
    """

    prompt = "[bold green]pb >[/]"

    #region main loop

    def cmdloop(self):
        """
        Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.
        """

        self.preloop()
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

    #endregion

    #region help

    def do_help(self, arg: str):
        """List available commands with "help" or detailed help with "help cmd"."""

        if arg:
            args = arg.split()

            if len(args) > 1:
                # if complex help query find exact function and print the function description
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
                # if help for main command find base function and print the function description
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
            # prints list of all commands
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

    #region exit

    def do_exit(self, arg: str) -> None:
        """Exit the shell."""

        raise ExitException

    #endregion
