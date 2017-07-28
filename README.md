# IDACyber
## Data Visualization Plugin for IDA Pro

![Alt text](/screenshots/screen02.png?raw=true "IDACyber")

IDACyber is a plugin for the Interactive Disassembler which is capable of visualizing the currently loaded IDB's data. This can be useful for identifying structures and patterns of binary blobs where extended information such as a header is not available (firmware dumps/images etc.).

### Requirements

* IDA Pro 7.x at a minimum

### Installation

Please copy idacyber.py along with the "cyber" subfolder to your IDA "plugins" folder.

### Usage

1. Press Ctrl-P to invoke the plugin

### Writing color filters

A color filter is nothing but a separate Python file that inherits from the ColorFilter class. Custom filters can be added by copying them to the "cyber" subfolder (idadir/plugins/).
For examples, please refer to the color filters located in the "cyber" subfolder.

### GUI, mouse and keyboard controls

1. Checkboxes

  * **Highlight cursor**: Displays the current mouse cursor on top of plotted data

2. Mouse controls

  * **Left mousebutton + mouse movement**: Vertical scrolling
  * **Mousewheel**: Fine grained vertical scrolling
  * **Double click**: Jump to address under cursor

3. Mouse Modifiers

  * **X**: Change width
  * **H**: Change width at 16byte boundary
  * **Shift**: Fine grained scrolling
  * **Ctrl**: Zoom

4. Keyboard shortcuts

  * **g** - Specify address to jump to
  * **F2** - Display information about current filter
  * **F12** - Export as bitmap 

![Alt text](/screenshots/idacyber.gif?raw=true "Visual pattern recognition")
