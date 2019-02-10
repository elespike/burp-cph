## Custom Parameter Handler extension for Burp Suite: a power tool for modifying HTTP messages with surgical precision, even when using macros.

#### The quicksave and quickload functionality persists through reloading not only the extension, but Burp Suite entirely. All values of each existing configuration tab will be saved, along with the order of all tabs.

#### Use the Export/Import Config buttons to save/load your current configuration to/from a JSON file.

### Manual installation

1. Download the [latest release](https://github.com/elespike/burp-cph/releases) file; e.g., `CustomParameterHandler_3.0.py`
2. Under _Extender_ > _Options_ > _Python Environment_, point Burp to the location of your copy of Jython's standalone .jar file.
  a. If you don't already have Jython's standalone .jar file, [download it here](http://www.jython.org/downloads.html).
3. Finally, add `CustomParamHandler_3.0.py` in _Extender_ > _Extensions_.

### Installation from the BApp store

1. Under _Extender_ > _Options_ > _Python Environment_, point Burp to the location of your copy of Jython's standalone .jar file.
  a. If you don't already have Jython's standalone .jar file, [download it here](http://www.jython.org/downloads.html).
2. Find and select _Custom Parameter Handler_ within the _Extender_ > _BApp Store_ tab, then click the _Install_ button.

### Adding configuration tabs

- Click '+' to add an empty tab; or
- Select one or many requests from anywhere in Burp, right-click, and choose _Send to CPH_.  
This will create as many tabs as the number of selected requests, and populate each tab with each selected request to be issued for parameter extraction.

### Enabling/Disabling configuration tabs

Simply click the checkbox next to the tab's name.
New tabs are enabled by default but require a valid configuration in order to have any effect.

### Reordering configuration tabs

- Click the '<' and '>' buttons to swap the currently selected tab with its preceding or succeeding neighbor.

Leftmost tabs will be processed first; therefore, tab order may be important, especially when extracting values from cached responses.

Visit the Wiki to learn more about [utilizing cached responses](https://github.com/elespike/burp-cph/wiki/08.-Utilizing-cached-responses).

### Tab configuration at a glance

#### _Scoping_
Depending on the selected option, this tab will take action on either:
- Requests only, Responses only, or both Requests and Responses; then either
  - All requests coming through Burp which are also in Burp's scope; or
  - Requests coming through Burp, in Burp's scope, and also matching the given expression.

#### _Parameter handling_
The supplied expression will be used to find the value that will be replaced with the replacement value.

RegEx features may be used to fine-tune modifications. Visit the Wiki to learn more.

When targeting a subset of matches, enter comma-separated, zero-based indices or slices (following Python's slice syntax).
  E.g.: `1,3,6:9` would act on the 2nd, 4th, 7th, 8th and 9th matches.

If not using a static value, the supplied expression will be used to find the desired replacement value.

### Please [visit the Wiki](https://github.com/elespike/burp-cph/wiki) for explanations on the remaining options.
