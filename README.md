## Custom Parameter Handler extension for Burp Suite, allowing manipulation of parameters with surgical precision even (and especially) when using macros.

#### The quicksave and quickload functionality persists through reloading not only the extension, but Burp Suite entirely. All values of each existing configuration tab will be saved, along with the order of all tabs.

##### Use the Export/Import Config buttons to save/load your current configuration to/from a file.

### Manual installation

1. Download and extract the latest release to a desired directory (let's call it *my_dir*).
2. Under Extender > Options > Python Environment, point Burp to the location of your copy of Jython's standalone .jar file.
3. Immediately underneath, configure Burp to use *my_dir* for loading modules.
4. Finally, add CustomParamHandler.py in Extender > Extensions.

### Installation from the BApp store

1. Under Extender > Options > Python Environment, point Burp to the location of your copy of Jython's standalone .jar file.
2. Find and select Custom Parameter Handler within the Extender > BApp Store tab, then click the Install button.

### Adding configuration tabs

- Click '+' to add an empty tab; or
Select one or many requests from anywhere in Burp, right-click, and choose 'Send to CPH'.
This will create as many tabs as the number of selected requests, and populate each tab with each selected request to be issued for parameter extraction.

### Enabling/Disabling configuration tabs

Simply click the checkbox next to the tab's name.
New tabs are enabled by default but require a valid configuration in order to have any effect.

### Reordering configuration tabs

- Click the '<' and '>' buttons to swap the currently selected tab with its preceding or succeeding neighbor.

Leftmost tabs will be processed first; therefore, tab order may be important, especially when extracting values from cached responses.

Visit our usage documentation for explanations on utilizing [cached responses](https://elespike.github.io/burp-cph/#expert/extract_cached).

### Tab configuration at a glance

##### Scoping
Depending on the selected option, this tab will take action on either:
- Requests only, Responses only, or both Requests and Responses; then either
  - All requests coming through Burp which are also in Burp's scope; or
  - Requests coming through Burp, in Burp's scope, and also matching the given expression.

##### Parameter handling
The supplied expression will be used to find the value that will either:
- Be appended with the replacement value; or
- Be entirely replaced with the replacement value.

When utilizing RegEx, using a group will constrain the match to the group's contents.
This strategy, therefore, increases match accuracy.

When targeting a subset of matches, enter comma-separated, zero-based indices or slices (following Python's slice syntax).
  E.g.: `1,3,6:9` would act on the 2nd, 4th, 7th, 8th and 9th matches.

If not using a static value, the supplied expression will be used to find
the desired replacement value.

When utilizing RegEx, using a group will constrain the match to the group's contents.
This strategy, therefore, increases match accuracy.

### Please [visit our usage documentation](https://elespike.github.io/burp-cph/) for explanations on the remaining options.
