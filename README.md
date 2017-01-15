# IDACyber
## Data Visualization Plugin for IDA Pro

![Alt text](/screenshots/screen02.png?raw=true "IDACyber")

IDACyber is a plugin for the Interactive Disassembler which visualizes the currently loaded database's data. This can be useful in identifying structures and patterns of binary blobs where extended information such as a header is not available (firmware dumps/images etc.). Moreover, the plugin adds Cyber to IDA. And it displays pixels. And whose tiring eyes don't like fancy pixelated graphics every now and then during excessive sessions of reading disassembled code all day?

### Installation

Please copy idacyber.py along with the "cyber" subfolder to your IDA "plugin" folder.

### Usage

1. Press Ctrl-P to invoke the plugin
2. Do stuff that looks fancy (bonus points for yelling "cyber" at random intervals)

### Writing filters

Custom filters can be added by copying them to the "cyber" subfolder. A filter should inherit from the ColorFilter class. Please refer to the examples located in the "cyber" subfolder.

### GUI, mouse and keyboard controls

1. Checkboxes

  * **Sync**: Synchronizes plotted data to IDA cursor and vice versa
  
  * **Highlight cursor**: Displays the current mouse cursor on top of plotted data

2. Mouse controls

  * **Left mousebutton + mouse movement**: Vertical scrolling

  * **Mousewheel**: Fine grained vertical scrolling

  * **Double click**: Jump to address under cursor

3. Mouse Modifiers

  * **Alt**: Horizontal scrolling

  * **Shift**: Fine grained scrolling

  * **Ctrl**: Zooming

4. Keyboard shortcuts

  * **g** - Specify address to jump to

![Alt text](/screenshots/verycyberpatternrecognition.gif?raw=true "Visual pattern recognition")
