## Custom Parameter Handler extension for Burp Suite, allowing manipulation of parameters with surgical precision even (and especially) when using macros.

#### The [save/load setup](https://github.com/elespike/burp-cph/wiki/0.-Save-and-load-configuration) functionality persists through reloading not only the extension, but Burp Suite entirely. All values of each existing configuration tab will be saved, along with the order of all tabs.

### Setting up Burp to use CPH

- Copy all .py files to a desired directory (let's call it *my_dir*). Note that tinyweb.py is not required; it is simply a little Flask app for a quick and easy CPH demo setup.
- Under Extender > Options > Python Environment, configure Burp to use *my_dir* for loading modules.
- If not already specified, browse to your copy of Jython's standalone .jar file.
- Finally, add CustomParamHandler.py in Extender > Extensions.

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

[Visit the wiki](https://github.com/elespike/burp-cph/wiki) for explanations on utilizing [cached responses](https://github.com/elespike/burp-cph/wiki/8.-Caching-messages-for-full-macro-modification).

### Tab configuration at a glance

#####Request modification/caching scope
Depending on the selected option, this tab will take action on either:
- All requests coming through Burp which are also in Burp's scope; or
- Requests coming through Burp, in Burp's scope, and also matching the given expression.

#####Parameter handling match options
The supplied expression will be used to find the value that will either:
- Be appended with the replacement value; or
- Be entirely replaced with the replacement value.

When utilizing RegEx, using a group will constrain the match to the group's contents.
This strategy, therefore, increases match accuracy.

The 'Match indices and/or slices' field controls which match(es) will be modified by the desired replacement value.
Enter comma-separated, zero-based indices or slices (following Python's slice syntax).
  E.g.: 1,3,6:9 would act on the 2nd, 4th, 7th, 8th and 9th matches.

#####Parameter handling replace options
If not using a static value, the supplied expression will be used to find
the desired replacement value.

When utilizing RegEx, using a group will constrain the match to the group's contents.
This strategy, therefore, increases match accuracy.

### Please [visit the wiki](https://github.com/elespike/burp-cph/wiki) for explanations on the remaining options.
