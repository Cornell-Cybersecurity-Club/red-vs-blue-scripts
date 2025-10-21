import logging
import logging.config
from abc import ABC, abstractmethod
from typing import Callable

from poochbotold import interpreter, options
from poochbotold.utils import *

logger = logging.getLogger(__name__)

class OptionNotConfiguredException(Exception):
    pass

class Module(ABC, interpreter.Interpreter):
    """Base class for modules that can be run within PoochBot"""

    name: str
    aliases: list[str] = []
    applies_to: list[OperatingSystem] = []
    warnings: list[str] = []

    def __init__(self) -> None:
        interpreter.Interpreter.__init__(self)

    @abstractmethod
    def run(self):
        pass

    def do_run(self, args: str) -> None:
        """Run the module."""

        if args:
            logger.error("Incorrect arguments provided to command.")
            return

        try:
            self.run()
        except:
            logger.critical(
                f"Uncaught error in {self.name}. Terminating module execution. Check logs for more information.",
                exc_info=True,
            )

    def do_exit(self, params):
        """Exit the currently loaded module."""
        
        raise ExitException

    # func_name = (requires(reqs))(func_name)
    # func_name = wrapper(func_name)
    def requires(*reqs: tuple[options.Option]) -> Callable:
        """Decorator that allows you to make sure certain options are set before running the specified function."""

        def wrapper(f: Callable):
            def wrapped_f(*args, **kwargs):

                try:
                    passed = all([r.value != None for r in reqs])
                except:
                    passed = False

                if passed:
                    return f(*args, **kwargs)
                else:
                    logger.error("Requirements for this command have not been set.")
                    return

            return wrapped_f

        return wrapper
