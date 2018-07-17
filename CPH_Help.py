########################################################################################################################
#  Begin CPH_Help.py Imports
########################################################################################################################

from collections import namedtuple

########################################################################################################################
#  End CPH_Help.py Imports
########################################################################################################################

########################################################################################################################
#  Begin CPH_Help.py
########################################################################################################################

class CPH_Help:
    quickstart = """<html>
    <strong>The quicksave and quickload functionality (see buttons above) persist through<br>
    reloading not only the extension, but Burp Suite entirely. All values of each existing<br>
    configuration tab will be saved, along with the order of all tabs.<br>
    <br>
    Use the Export/Import Config buttons to save/load your current configuration to/from a file.<br></strong>
    <br>
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
    <h2>Tips and notes</h2>
    &nbsp;&nbsp;&nbsp;&nbsp;- Leftmost tabs will be processed first; therefore, tab order may be important,<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;especially when extracting values from cached responses.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Please view the full guide for explanations on utilizing cached responses.<br>
    <br>
    &nbsp;&nbsp;&nbsp;&nbsp;- When utilizing RegEx, using a group will constrain the match to the group's contents.<br>
    &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;This strategy, therefore, increases match accuracy.<br>
    </html>"""

    HelpPopup = namedtuple('HelpPopup', 'title, message')

    indices = HelpPopup(
        'Targeting a subset of matches',
        """<html>
        To target a specific subset of matches,<br>
        enter comma-separated indices and/or slices, such as:<br>
        0,3,5,7 - targets the 1st, 4th, 6th and 8th matches<br>
        0:7&nbsp;&nbsp;&nbsp;&nbsp; - targets the first 7 matches but not the 8th match<br>
        0:7,9&nbsp;&nbsp; - targets the first 7 matches and the 10th match<br>
        -1,-2&nbsp;&nbsp; - targets the last and penultimate matches<br>
        0:-1&nbsp;&nbsp;&nbsp; - targets all but the last match
        </html>"""
    )

    named_groups = HelpPopup(
        'Inserting a dynamic value using named groups',
        """<html>
        TODO
        </html>"""
    )

    extract_single = HelpPopup(
        'Extracting a value after issuing a request',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value depends on another request to be issued,<br>
        set up the request on the left pane and craft a RegEx<br>
        to extract the desired value from its response.<br>
        <br>
        The <b>Issue</b> button may be used to test the request,<br>
        helping ensure a proper response.
        </html>"""
    )

    extract_macro = HelpPopup(
        'Extracting a value after issuing sequential requests',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value depends on sequential requests to be issued,<br>
        set up a Burp Suite Macro and invoke the CPH handler<br>
        from the Macro's associated Session Handling Rule.<br>
        <br>
        Finally, craft a RegEx to extract the desired value<br>
        from the final Macro response.
        </html>"""
    )

    extract_cached = HelpPopup(
        'Extracting a value from a previous tab',
        """<html>
        To replace your target match(es) with a value<br>
        or append a value to your target match(es) when<br>
        that value has been cached by a previous CPH tab,<br>
        simply select the desired tab from the dynamic drop-down.<br>
        <i>NOTE: If the desired tab is not in the drop-down, ensure<br>
        that the tab has seen its request at least once.</i><br>
        <br>
        Then, craft a RegEx to extract the desired value<br>
        from the selected tab's cached response.<br>
        Note that disabled tabs will still cache HTTP messages<br>
        and therefore can be used as a mechanism for value extraction.
        </html>"""
    )

    def __init__(self):
        pass

########################################################################################################################
#  End CPH_Help.py
########################################################################################################################

