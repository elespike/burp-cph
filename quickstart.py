########################################################################################################################
#  Begin Quickstart.py
########################################################################################################################

class Quickstart:
    text = """<html>
    <h3>First and foremost: the quicksave and quickload functionality (see buttons above) persists through<br>
    reloading not only the extension, but Burp Suite entirely. All values of each existing<br>
    configuration tab will be saved, along with the order of all tabs.</h3>
    <h3>Use the Export/Import Config buttons to save/load your current configuration to/from a file.</h3>
    <h2>Adding configuration tabs</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;- Click '+' to add an empty tab; or<br>
    &nbsp;&nbsp;&nbsp;&nbsp;- Select one or many requests from anywhere in Burp, right-click, and choose 'Send to CPH'.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This will create as many tabs as the number of selected requests, and populate each tab<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;with each selected request to be issued for parameter extraction.<br>
    <br>
    <h2>Enabling/Disabling configuration tabs</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Simply click the checkbox next to the tab's name.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;New tabs are enabled by default but require a valid configuration in order to have any effect.<br>
    <br>
    <h2>Reordering configuration tabs</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;- Click the '&lt;' and '&gt;' buttons to swap the currently selected tab<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;with its preceding or succeeding neighbor.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Leftmost tabs will be processed first; therefore, tab order may be important,<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;especially when extracting values from cached responses.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;View the full guide for explanations on utilizing cached responses.<br>
    <br>
    <h2>Tab configuration at a glance</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;&gt;&nbsp;Request modification/caching scope<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Depending on the selected option, this tab will take action on either:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Requests only, Responses only, or both Requests and Responses; then either<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;~ All requests coming through Burp which are also in Burp's scope; or<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;~ Requests coming through Burp, in Burp's scope, and also matching the given expression.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&gt;&nbsp;Parameter handling match options<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The supplied expression will be used to find the value that will either:<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Be appended with the replacement value; or<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;- Be entirely replaced with the replacement value.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;When utilizing RegEx, using a group will constrain the match to the group's contents.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This strategy, therefore, increases match accuracy.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;The 'Match indices and/or slices' field controls which match(es) will be modified<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;by the desired replacement value.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enter comma-separated, zero-based indices or slices (following Python's slice syntax).<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;E.g.: 1,3,6:9 would act on the 2nd, 4th, 7th, 8th and 9th matches.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&gt;&nbsp;Parameter handling replace options<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;If not using a static value, the supplied expression will be used to find<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;the desired replacement value.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;When utilizing RegEx, using a group will constrain the match to the group's contents.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This strategy, therefore, increases match accuracy.<br>
    <h2>Please view the full guide for explanations on the remaining options.</h2>
    </html>"""
    
    def __init__(self):
        pass

########################################################################################################################
#  End Quickstart.py
########################################################################################################################
