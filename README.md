# IDACyber
## Data Visualization Plugin for IDA Pro

![IDACyber IDA Pro plugin](/screenshots/idacyber.png?raw=true "IDACyber")

IDACyber is a plugin for the Interactive Disassembler that visualizes an IDA database's content. This includes dynamic content taken from memory/debug segments such as the stack and heap. The plugin can be extended with custom "ColorFilters" that allow data to be represented in unique ways, allowing for patterns and interesting areas to be identified and highlighted.

### Requirements

* IDACyber requires IDA Pro 7.x

### Installation

* The file "idacyber.py" and the "cyber" folder must be copied to the IDA Pro "plugins" folder.

### Usage

* Ctrl-Shift-C starts the plugin and creates a new dockable window. Multiple instances can be created by re-running the plugin which allows several ColorFilters to be run in parallel. The resulting image can be interacted with using the following controls.

### GUI, mouse and keyboard controls

1. Checkboxes

  * **Sync**: Synchronize graph and IDA cursor

2. Mouse controls

  * **Left mousebutton + mouse movement**: Vertical scrolling
  * **Mousewheel**: Fine grained vertical scrolling
  * **Double click**: Jump to address under cursor

3. Mouse Modifiers

  * **X**: Change width (X axis)
  * **H**: Change width at 16byte boundary (X axis)
  * **Shift**: Fine grained scrolling
  * **Ctrl**: Zoom

4. Keyboard shortcuts

  * **Minus** - Scroll up
  * **Plus** - Scroll down
  * **Page up** - Scroll page up
  * **Page down** - Scroll page down
  * **Ctrl-Plus** - Zoom in
  * **Ctrl-Minus** - Zoom out
  * **g** - Specify address to jump to
  * **s** - Toggle 'sync' on/off
  * **F2** - Display help/information about the current ColorFilter
  * **F12** - Export current graph as bitmap 

### Writing custom color filters

A color filter is nothing but a separate Python file that inherits from the ColorFilter class (please refer to "idacyber.py" for details). Custom filters can be added by copying them to the "cyber" subfolder (idadir/plugins/). For code examples, please have a look at the color filters located in the "cyber" subfolder.

### Known bugs

Yes :[

### Gallery

The following shows an excerpt of the color filters available for IDACyber:

![IDACyber Gallery 01](/screenshots/screen03.png?raw=true "IDACyber")
![IDACyber Gallery 02](/screenshots/screen04.png?raw=true "IDACyber")
![IDACyber Gallery 03](/screenshots/screen05.png?raw=true "IDACyber")
![IDACyber Gallery 04](/screenshots/screen06.png?raw=true "IDACyber")
![IDACyber animated](/screenshots/idacyber.gif?raw=true "Visual pattern recognition")
