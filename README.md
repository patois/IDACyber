# IDACyber
## Data Visualization Plugin for IDA Pro

IDACyber is an interactive data visualization plugin for IDA Pro. It consists of external "color filters" that transform raw data bytes into a canvas that can be used to inspect and navigate data interactively. Depending on the filter in context, browsing this data visually can reveal particular structures and patterns, literally from a zoomed-out perspective.

![scrn0](/rsrc/0.png?raw=true "IDACyber")

### Requirements

* IDA 7.3+
* This IDAPython project is compatible with Python3 only. For compatibility with older versions of IDA, you may want to check out the Python2 branch of this project. The Python2 branch is no longer maintained and thus contains outdated code.

### Installation

* Updating: It's recommended to delete "idacyber.py" and the "cyber" folder if you're updating from a previous IDACyber version.
* Installation: Copy "idacyber.py" and the "cyber" folder to the IDA Pro "plugins" folder.

### Usage

Ctrl-Shift-C starts the plugin and creates a new dockable window. Multiple instances can be created by re-running the plugin which allows several color filters to be run in parallel. The resulting canvas can be interacted with using keyboard and mouse controls. With an instance of IDACyber on focus, a quick manual can be opened by pressing Ctrl-F1, help about the currently active filter can be shown by pressing Ctrl-F2.

![scrn10](/rsrc/10.png?raw=true "IDACyber")
![scrn11](/rsrc/11.png?raw=true "IDACyber")

### Writing custom color filters

IDACyber is meant to be easily customizable by offering the ability to add new "color filters" to it.
A color filter is an external IDAPython script that must be placed within the "cyber" folder, which IDACyber will then load during startup. Its main workhorse consists of the callback function "on_process_buffer()" which each color filter is expected to implement. This function is passed the raw data to be processed by a color filter, which then is supposed to return a list of colors in RGB format. IDACyber will take this list of colors and draw it onto the interactive canvas.

For example code, please check out the existing color filters that can be found in the "cyber" folder. The two filters "NES" and "GameBoy" are two simple examples that can be used as a basic skeleton for writing new color filters.

### Example filters

![scrn1](/rsrc/1.png?raw=true "IDACyber")
![scrn2](/rsrc/2.png?raw=true "IDACyber")
![scrn3](/rsrc/3.png?raw=true "IDACyber")
![scrn4](/rsrc/4.png?raw=true "IDACyber")
![scrn5](/rsrc/5.png?raw=true "IDACyber")
![scrn6](/rsrc/6.png?raw=true "IDACyber")
![scrn7](/rsrc/7.png?raw=true "IDACyber")
![scrn8](/rsrc/8.png?raw=true "IDACyber")
![scrn9](/rsrc/9.png?raw=true "IDACyber")


### Known bugs

Yes :[
