import typing

from poochbotold.utils import *

class Option:
    """Base class for options with built in set and get features"""

    name: str
    value: typing.Any
    type_: type

    def __init__(self, name: str, value: typing.Any = None, type_: type = None):
        self.name = name

        if value == None and type_ == None:
            raise ValueError("Must specify either value or type_.")
        
        self.value = value

        if type_ == None:
            self.type_ = type(value)
        else:
            self.value = value
            self.type_ = type_

    def set_value(self, value):
        """Sets the value of this option"""

        # TODO: create a system that allows for setting variables as enum types (this will take a while lol)
        # if not isinstance(value, self.type_) and not issubclass(
        #     type(value), self.type_
        # ):
        # raise ValueError("Incorrect type of variable.")
        self.value = value

    def get_value_as_text(self, expressive=False):
        """Gets the value of this option as text for printing"""

        if expressive:
            match self.value:
                case str():
                    return f'"{self.value}"'
                case list():
                    return f'[{", ".join([str(value) for value in self.value])}]'
                case None:
                    return "[red]Not set"
                case _:
                    return str(self.value)
        else:
            match self.value:
                case list():
                    return ", ".join([str(value) for value in self.value])
                case None:
                    return "[red]Not set"
                case _:
                    return str(self.value)

OPTIONS: dict[str, Option] = {
    "OS": Option("OS", type_=OperatingSystem),
    "OS_VERSION": Option("OS", type_=OperatingSystemVersion),
    "SERVICES": Option("SERVICES", value=[], type_=list[CriticalService]),
    "USERS": {
        "ACTIVE_USER": Option("ACTIVE_USER", type_=str),
        "ADMIN_USERS": Option("ADMIN_USERS", type_=list[str]),
        "STD_USERS": Option("STD_USERS", type_=list[str]),
    },
}
