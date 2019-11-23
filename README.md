# IDACyber
## Data Visualization Plugin for IDA Pro

![IDACyber IDA Pro plugin](/screenshots/idacyber.png?raw=true "IDACyber")

IDACyber is an interactive data visualization plugin for IDA Pro.

![IDACyber animation](/gallery/cyber.gif?raw=true "IDACyber animated gif")

Be sure to check out the ![gallery](/gallery/ "gallery")

### Requirements

* IDA 7.3+
* This IDAPython project is compatible with Python3. For compatibility with older versions of IDA, you may want to check out the Python2 branch of this project.

### Installation

* Copy "idacyber.py" and the "cyber" folder to the IDA Pro "plugins" folder.

### Usage

* Ctrl-Shift-C starts the plugin and creates a new dockable window. Multiple instances can be created by re-running the plugin which allows several ColorFilters to be run in parallel. The resulting graph can be interacted with using keyboard and mouse controls. With an instance of IDACyber running, the quick manual can be opened by pressing Ctrl-F1.

### Writing custom color filters

An IDACyber color filter is nothing but a separate Python file that inherits from the ColorFilter class (please refer to "idacyber.py" for details). Color filters must be placed into the "plugins/cyber" subfolder. For code examples, please have a look at the existing color filters located in the "cyber" subfolder.

### Known bugs

Yes :[
