import json
import os
import typing

from poochbot.utils import *

logger = logging.getLogger(__name__)

save_dir = "./Data"
save_file = "options.json"
save_path = save_dir + "/" + save_file

default_file = "optionsdefault.json"
default_path = save_dir + "/" + default_file

#region options objects

# IMPORTANT: if you add a new type to this schema please update match_types to make sure it can be correctly parsed as needed -Nolan
OPTIONS_SCHEMA: dict[str, typing.Any] = {
    "OS": OperatingSystem,
    "OS_VERSION": OperatingSystemVersion,
    "SERVICES": list[CriticalService],
    "USERS": {
        "ACTIVE_USER": str,
        "ADMIN_USERS": list[str],
        "STD_USERS": list[str],
    },
}

OPTIONS_DEFAULTS: dict[str, typing.Any] = {
    "OS": OperatingSystem.NONE,
    "OS_VERSION": OperatingSystemVersion.NONE,
    "SERVICES": [],
    "USERS": {
        "ACTIVE_USER": "",
        "ADMIN_USERS": [],
        "STD_USERS": [],
    },
}

OPTIONS = {}

#endregion

#region saving and loading

def save_options() -> None:
    """Save options as json file"""

    # read old file data incase of failed dump
    oldfiledata = ""
    with open(save_path, "r") as f:
        oldfiledata = f.read()

    try:
        # try to serialize current options into options file
        with open(save_path, "w") as f:
            json.dump(OPTIONS, f, indent=4)
    except:
        # revert changes if failed to serialize
        logger.error("Failed to save options.json undoing changes")
        with open(save_path, "w") as f:
            f.write(oldfiledata)

def load_options() -> None:
    """Load options from json file"""

    with open(save_path, "r") as f:
        NEWOPTIONS = {}
        try:
            NEWOPTIONS = json.load(f)
        except:
            NEWOPTIONS = {}
        
        for key in NEWOPTIONS.keys():
            OPTIONS[key] = NEWOPTIONS[key]
    
    match_types(OPTIONS, OPTIONS_SCHEMA, OPTIONS_DEFAULTS)

#endregion

#region match types

def match_types(dic : dict[str, typing.Any], typedic : dict[str, typing.Any], defdic : dict[str, typing.Any]) -> None:
    """Make sure that all values match their correct types. If not revert to default"""

    for key, value in typedic.items():

        if not key in dic.keys():
            # key does not exist so reverting to default
            dic[key] = defdic[key]
            logger.error(f"Option: {key} did not exist. Reverting to default value of: {defdic[key]}")
        elif isinstance(typedic[key], dict):
            # if key is subcatagory iterate through those values
            match_types(dic[key], typedic[key], defdic[key])
        elif not isinstance(dic[key], type(typedic[key])):
            # try to ensure values are of correct type
            try:
                fixtype(dic, typedic, key)
            except:
                # failed to convert so reverting to default
                dic[key] = defdic[key]
                logger.error(f"Option: {key} could not be read. Reverting to default value of: {defdic[key]}")

def fixtype(dic : dict[str, typing.Any], typedic : dict[str, typing.Any], key : str) -> None:
    """Mappings to fix each type (usually works if it is a string)"""

    if typedic[key] is OperatingSystem:
        dic[key] = OperatingSystem(dic[key])

    elif typedic[key] is OperatingSystemVersion:
        dic[key] = OperatingSystemVersion(dic[key])

    elif typedic[key] is list[CriticalService]:
        newlist = list[CriticalService]
        for val in dic[key]:
            newlist.append(CriticalService(val))
        dic[key] = newlist

    elif typedic[key] is str:
        dic[key] = str(dic[key])
        
    elif typedic[key] is list[str]:
        newlist = list[str]
        for val in dic[key]:
            newlist.append(str(val))
        dic[key] = newlist

#endregion

#region init

def resetoptionsfile() -> None:
    """Resets the options file back to the default"""

    with open(save_path, "w") as f:
        json.dump(OPTIONS_DEFAULTS, f)

def initoptionsfile() -> None:
    """If no options file is saved create one using default, else read current"""

    logger.info("Initializing options")

    # if options file doesn't exist make default one
    if not os.path.exists(save_path):
        logger.info("Generating default options")

        # write default options to file
        if not os.path.exists(save_dir):
            os.mkdir(save_dir)
        resetoptionsfile()
    else:
        logger.info("Reading existing options.json")

    # whether having written defaults to file or reading new data load file!
    load_options()

    # save to make sure all type errors are fixed
    save_options()
    
    logger.info("Options initialized")

#endregion
