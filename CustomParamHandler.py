########################################################################################################################
#  Begin CustomParameterHandler.py Imports
########################################################################################################################

from datetime import datetime as dt
from sys      import stdout
from urllib   import quote

from logging import (
    Formatter    ,
    INFO         ,
    StreamHandler,
    getLogger    ,
)
from re import (
    compile  as re_compile ,
    error    as re_error   ,
    findall  as re_findall ,
    finditer as re_finditer,
    search   as re_search  ,
    split    as re_split   ,
    sub      as re_sub     ,
)

from CPH_Config  import MainTab
from burp        import IBurpExtender
from burp        import IContextMenuFactory
from burp        import IExtensionStateListener
from burp        import IHttpListener
from burp        import ISessionHandlingAction
from javax.swing import JMenuItem

########################################################################################################################
#  End CustomParameterHandler.py Imports
########################################################################################################################

########################################################################################################################
#  Begin CustomParameterHandler.py
########################################################################################################################

class BurpExtender(IBurpExtender, IContextMenuFactory, IExtensionStateListener, IHttpListener, ISessionHandlingAction):
    def __init__(self):
        self.messages_to_send = []
        self.final_macro_resp = ''

        self.logger = getLogger(__name__)
        self.initialize_logger()

    def initialize_logger(self):
        fmt = '%(asctime)s:%(msecs)03d [%(levelname)s] %(message)s\n'
        datefmt = '%H:%M:%S'
        formatter = Formatter(fmt=fmt, datefmt=datefmt)

        handler = StreamHandler(stream=stdout)
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(INFO)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers   = callbacks.getHelpers()
        self.maintab   = MainTab(self)
        callbacks.setExtensionName('Custom Parameter Handler')
        callbacks.registerContextMenuFactory(self)
        callbacks.registerExtensionStateListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        callbacks.addSuiteTab(self.maintab)

    def getActionName(self):
        return 'CPH: extract replace value from the final macro response'

    def performAction(self, currentRequest, macroItems):
        if not macroItems:
            self.logger.error('No macro found, or macro is empty!')
            return
        self.final_macro_resp = self.helpers.bytesToString(macroItems[-1].getResponse())

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        if context == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST \
        or context == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST \
        or context == invocation.CONTEXT_PROXY_HISTORY          \
        or context == invocation.CONTEXT_TARGET_SITE_MAP_TABLE  \
        or context == invocation.CONTEXT_SEARCH_RESULTS:
            self.messages_to_send = invocation.getSelectedMessages()
            if len(self.messages_to_send):
                return [JMenuItem('Send to CPH', actionPerformed=self.send_to_cph)]
        else:
            return None

    def send_to_cph(self, e):
        self.maintab.add_config_tab(self.messages_to_send)

    def extensionUnloaded(self):
        try:
            while self.maintab.options_tab.emv_tab_pane.getTabCount():
                self.maintab.options_tab.emv_tab_pane.remove(
                    self.maintab.options_tab.emv_tab_pane.getTabCount() - 1
                )
            self.maintab.options_tab.emv.dispose()
        except AttributeError:
            self.logger.warning(
                'Effective Modification Viewer not found! You may be using an outdated version of CPH!'
            )

        while self.maintab.mainpane.getTabCount():
            # For some reason, the last tab isn't removed until the next loop,
            # hence the try/except block with just a continue. Thx, Java.
            try:
                self.maintab.mainpane.remove(
                    self.maintab.mainpane.getTabCount() - 1
                )
            except:
                continue

    def issue_request(self, tab):
        tab.request = tab.param_handl_request_editor.getMessage()

        issuer_config = tab.get_socket_pane_config(tab.param_handl_issuer_socket_pane)
        host  = issuer_config.host
        port  = issuer_config.port
        https = issuer_config.https

        tab.request = self.update_content_length(tab.request, True)
        tab.param_handl_request_editor.setMessage(tab.request, True)

        try:
            httpsvc = self.helpers.buildHttpService(host, port, https)
            response_bytes = self.callbacks.makeHttpRequest(httpsvc, tab.request).getResponse()
            self.logger.debug('Issued configured request from tab "{}" to host "{}:{}"'.format(
                tab.namepane_txtfield.getText(),
                httpsvc.getHost(),
                httpsvc.getPort()
            ))
            if response_bytes:
                tab.param_handl_response_editor.setMessage(response_bytes, False)
                tab.response = response_bytes
                self.logger.debug('Got response!')
        # Generic except because misc. Java exceptions might occur.
        except:
            self.logger.exception('Error issuing configured request from tab "{}" to host "{}:{}"'.format(
                tab.namepane_txtfield.getText(),
                host,
                port
            ))
            tab.response = self.helpers.stringToBytes('Error! See extension output for details.')
            tab.param_handl_response_editor.setMessage(tab.response, False)

    def update_content_length(self, message_bytes, is_request):
        if is_request:
            message_info = self.helpers.analyzeRequest(message_bytes)
        else:
            message_info = self.helpers.analyzeResponse(message_bytes)

        content_length = len(message_bytes) - message_info.getBodyOffset()
        msg_as_string = self.helpers.bytesToString(message_bytes)
        msg_as_string = re_sub(
            'Content-Length: \d+\r\n',
            'Content-Length: {}\r\n'.format(content_length),
            msg_as_string,
            1
        )
        return self.helpers.stringToBytes(msg_as_string)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        dbg_skip_tool = 'Skipping message received from {} on account of global tool scope options.'
        if toolFlag == self.callbacks.TOOL_PROXY:
            if not self.maintab.options_tab.chkbox_proxy.isSelected():
                self.logger.debug(dbg_skip_tool.format('Proxy'))
                return
        elif toolFlag == self.callbacks.TOOL_TARGET:
            if not self.maintab.options_tab.chkbox_target.isSelected():
                self.logger.debug(dbg_skip_tool.format('Target'))
                return
        elif toolFlag == self.callbacks.TOOL_SPIDER:
            if not self.maintab.options_tab.chkbox_spider.isSelected():
                self.logger.debug(dbg_skip_tool.format('Spider'))
                return
        elif toolFlag == self.callbacks.TOOL_REPEATER:
            if not self.maintab.options_tab.chkbox_repeater.isSelected():
                self.logger.debug(dbg_skip_tool.format('Repeater'))
                return
        elif toolFlag == self.callbacks.TOOL_SEQUENCER:
            if not self.maintab.options_tab.chkbox_sequencer.isSelected():
                self.logger.debug(dbg_skip_tool.format('Sequencer'))
                return
        elif toolFlag == self.callbacks.TOOL_INTRUDER:
            if not self.maintab.options_tab.chkbox_intruder.isSelected():
                self.logger.debug(dbg_skip_tool.format('Intruder'))
                return
        elif toolFlag == self.callbacks.TOOL_SCANNER:
            if not self.maintab.options_tab.chkbox_scanner.isSelected():
                self.logger.debug(dbg_skip_tool.format('Scanner'))
                return
        elif toolFlag == self.callbacks.TOOL_EXTENDER:
            if not self.maintab.options_tab.chkbox_extender.isSelected():
                self.logger.debug(dbg_skip_tool.format('Extender'))
                return
        else:
            self.logger.debug('Skipping message received from unsupported Burp tool.')
            return

        requestinfo = self.helpers.analyzeRequest(messageInfo)
        requesturl  = requestinfo.getUrl()

        if not self.callbacks.isInScope(requesturl):
            return

        # Leave these out of the 'if' statement; the 'else' needs req_as_string.
        request_bytes = messageInfo.getRequest()
        req_as_string = self.helpers.bytesToString(request_bytes)
        if messageIsRequest:
            original_req  = req_as_string
            for tab in self.maintab.get_config_tabs():
                if request_bytes == tab.request:
                    continue

                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(req_as_string, messageIsRequest, tab):

                    self.logger.info('Sending request to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))

                    req_as_string = self.modify_message(tab, req_as_string)
                    if req_as_string != original_req:
                        if tab.param_handl_auto_encode_chkbox.isSelected():
                            # URL-encode the first line of the request, since it was modified
                            first_req_line_old = req_as_string.split('\r\n')[0]
                            self.logger.debug('first_req_line_old:\n{}'.format(first_req_line_old))
                            first_req_line_old = first_req_line_old.split(' ')
                            first_req_line_new = '{} {} {}'.format(
                                first_req_line_old[0],
                                ''.join([quote(char, safe='/%+=?&') for char in '%20'.join(first_req_line_old[1:-1])]),
                                first_req_line_old[-1]
                            )
                            self.logger.debug('first_req_line_new:\n{}'.format(first_req_line_new))
                            req_as_string = req_as_string.replace(
                                ' '.join(first_req_line_old),
                                first_req_line_new
                            )
                            self.logger.debug('Resulting first line of request:\n{}'.format(
                                req_as_string.split('\r\n')[0]
                            ))

                        request_bytes = self.helpers.stringToBytes(req_as_string)

                    forwarder_config = tab.get_socket_pane_config(tab.param_handl_forwarder_socket_pane)
                    host  = forwarder_config.host
                    port  = forwarder_config.port
                    https = forwarder_config.https

                    # TODO make a checkbox?
                    request_bytes = self.update_content_length(request_bytes, messageIsRequest)
                    req_as_string = self.helpers.bytesToString(request_bytes)

                    if req_as_string != original_req:
                        tab.emv_tab.add_table_row(dt.now().time(), True, original_req, req_as_string)

                    if tab.param_handl_enable_forwarder_chkbox.isSelected():
                        try:
                            messageInfo.setHttpService(self.helpers.buildHttpService(host, int(port), https))
                            httpsvc = messageInfo.getHttpService()
                            self.logger.info('Tab "{}" is re-routing its request to "{}:{}"'.format(
                                tab.namepane_txtfield.getText(),
                                httpsvc.getHost(),
                                httpsvc.getPort()
                            ))
                        # Generic except because misc. Java exceptions might occur.
                        except:
                            self.logger.exception('Error re-routing request:')

            messageInfo.setRequest(request_bytes)

        if not messageIsRequest:
            response_bytes = messageInfo.getResponse()
            resp_as_string = self.helpers.bytesToString(response_bytes)
            original_resp  = resp_as_string

            for tab in self.maintab.get_config_tabs():
                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(resp_as_string, messageIsRequest, tab):

                    self.logger.info('Sending response to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))

                    resp_as_string = self.modify_message(tab, resp_as_string)
                    response_bytes = self.helpers.stringToBytes(resp_as_string)
                    response_bytes = self.update_content_length(response_bytes, messageIsRequest)
                    resp_as_string = self.helpers.bytesToString(response_bytes)

                    if resp_as_string != original_resp:
                        tab.emv_tab.add_table_row(dt.now().time(), False, original_resp, resp_as_string)

            messageInfo.setResponse(response_bytes)

            for working_tab in self.maintab.get_config_tabs():
                selected_item = working_tab.param_handl_combo_cached.getSelectedItem()
                if self.is_in_cph_scope(req_as_string , True , working_tab)\
                or self.is_in_cph_scope(resp_as_string, False, working_tab):
                    working_tab.cached_request  = request_bytes
                    working_tab.cached_response = response_bytes
                    self.logger.debug('Messages cached for tab {}!'.format(
                        working_tab.namepane_txtfield.getText()
                    ))
                # If this tab is set to extract a value from one of the previous tabs,
                # update its cached message panes with that tab's cached messages.
                for previous_tab in self.maintab.get_config_tabs():
                    if previous_tab == working_tab:
                        break
                    item = previous_tab.namepane_txtfield.getText()
                    if item == selected_item:
                        working_tab.param_handl_cached_req_viewer .setMessage(previous_tab.cached_request , True)
                        working_tab.param_handl_cached_resp_viewer.setMessage(previous_tab.cached_response, False)

    def is_in_cph_scope(self, msg_as_string, is_request, tab):
        rms_scope_all  = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_ALL
        rms_scope_some = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_SOME

        rms_type_requests  = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_REQ
        rms_type_responses = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_RESP
        rms_type_both      = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_BOTH

        rms_scope_exp = tab.get_exp_pane_expression(tab.msg_mod_exp_pane_scope)

        if is_request and (rms_type_requests or rms_type_both):
            pass
        elif not is_request and (rms_type_responses or rms_type_both):
            pass
        else:
            self.logger.debug('Preliminary scope check negative!')
            return False

        if rms_scope_all:
            return True
        elif rms_scope_some and rms_scope_exp:
            regexp = re_compile(rms_scope_exp)
            if regexp.search(msg_as_string):
                return True
        else:
            self.logger.warning('Scope restriction is active but no expression was specified. Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()
            ))
        return False

    def modify_message(self, tab, msg_as_string):
        ph_matchnum_txt = tab.param_handl_txtfield_match_indices.getText()

        ph_target_exp         = tab.get_exp_pane_expression(tab.param_handl_exp_pane_target        )
        ph_extract_static_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_static)
        ph_extract_single_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_single)
        ph_extract_macro_exp  = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_macro )
        ph_extract_cached_exp = tab.get_exp_pane_expression(tab.param_handl_exp_pane_extract_cached)

        if not ph_target_exp:
            self.logger.warning(
                'No match expression specified! Skipping tab "{}".'.format(
                    tab.namepane_txtfield.getText()
                )
            )
            return msg_as_string

        exc_invalid_regex = 'Skipping tab "{}" due to error in expression {{}}: {{}}'.format(
            tab.namepane_txtfield.getText()
        )

        try:
            match_exp = re_compile(ph_target_exp)
        except re_error as e:
            self.logger.error(exc_invalid_regex.format(ph_target_exp, e))
            return msg_as_string

        # The following code does not remove support for groups,
        # as the original expression will be used for actual replacements.
        # We simply need an expression without capturing groups to feed into re.findall(),
        # which enables the logic for granular control over which match indices to target.

        # Removing named groups to normalize capturing groups.
        findall_exp = re_sub('\?P<.+?>', '', ph_target_exp)
        # Removing capturing groups to search for full matches only.
        findall_exp = re_sub(r'(?<!\\)\(([^?]*?)(?<!\\)\)', '\g<1>', findall_exp)
        findall_exp = re_compile(findall_exp)
        self.logger.debug('findall_exp: {}'.format(findall_exp.pattern))

        all_matches = re_findall(findall_exp, msg_as_string)
        self.logger.debug('all_matches: {}'.format(all_matches))

        match_count = len(all_matches)
        if not match_count:
            self.logger.warning(
                'Skipping tab "{}" because this expression found no matches: {}'.format(
                    tab.namepane_txtfield.getText(),
                    ph_target_exp
                )
            )
            return msg_as_string

        matches     = list()
        dyn_values  = ''
        replace_exp = ph_extract_static_exp

        if tab.param_handl_dynamic_chkbox.isSelected():
            find_exp, target_txt = '', ''
            selected_item = tab.param_handl_combo_extract.getSelectedItem()

            if selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                find_exp, target_txt = ph_extract_cached_exp, tab.param_handl_cached_resp_viewer.getMessage()
                target_txt = self.helpers.bytesToString(target_txt)

            elif selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_SINGLE:
                self.issue_request(tab)
                find_exp, target_txt = ph_extract_single_exp, self.helpers.bytesToString(tab.response)

            elif selected_item == tab.PARAM_HANDL_COMBO_EXTRACT_MACRO:
                find_exp, target_txt = ph_extract_macro_exp, self.final_macro_resp

            if not find_exp:
                self.logger.warning(
                    'No dynamic value extraction expression specified! Skipping tab "{}".'.format(
                        tab.namepane_txtfield.getText()
                    )
                )
                return msg_as_string

            try:
                # Making a list to enable multiple iterations.
                matches = list(re_finditer(find_exp, target_txt))
            except re_error as e:
                self.logger.error(exc_invalid_regex.format(ph_extract_macro_exp, e))
                return msg_as_string

            if not matches:
                self.logger.warning('Skipping tab "{}" because this expression found no matches: {}'.format(
                    tab.namepane_txtfield.getText(),
                    find_exp
                ))
                return msg_as_string

            groups = {}
            groups_keys = groups.viewkeys()
            for match in matches:
                gd = match.groupdict()
                # The given expression should have unique group matches.
                for k in gd.keys():
                    if k in groups_keys:
                        self.logger.warning('Skipping tab "{}" because this expression found ambiguous matches: {}'.format(
                            tab.namepane_txtfield.getText(),
                            find_exp
                        ))
                        return msg_as_string
                groups.update(gd)

            exp = ph_target_exp
            parens = ''
            while exp.endswith(')'):
                exp = exp[:-1]
                parens += ')'

            groups_exp = ''.join(['(?P<{}>{})'.format(group_name, group_match) for group_name, group_match in groups.items()])
            dyn_values = ''.join(groups.values())

            # No need for another try/except around this re.compile(),
            # as ph_target_exp was already checked when compiling match_exp earlier.
            match_exp = re_compile(exp + groups_exp + parens)
            self.logger.debug('match_exp adjusted to: {}'.format(match_exp.pattern))

        subsets = ph_matchnum_txt.replace(' ', '').split(',')
        match_indices = []
        for subset in subsets:
            try:
                if ':' in subset:
                    sliceindex = subset.index(':')
                    start = int(subset[:sliceindex   ])
                    end   = int(subset[ sliceindex+1:])
                    if start < 0:
                        start = match_count + start
                    if end < 0:
                        end = match_count + end
                    for match_index in range(start, end):
                        match_indices.append(match_index)
                else:
                    match_index = int(subset)
                    if match_index < 0:
                        match_index = match_count + match_index
                    match_indices.append(match_index)
            except ValueError as e:
                self.logger.error(
                    'Ignoring invalid match index or slice on tab "{}" due to {}'.format(
                        tab.namepane_txtfield.getText(),
                        e
                    )
                )
                continue

        match_indices = set(sorted([m for m in match_indices if m < match_count]))
        self.logger.debug('match_indices: {}'.format(match_indices))

        # Using findall_exp to avoid including capture groups in the result.
        message_parts = re_split(findall_exp, msg_as_string)
        self.logger.debug('message_parts: {}'.format(message_parts))

        modified_message  = ''
        remaining_indices = list(match_indices)
        for part_index, message_part in enumerate(message_parts):
            combined_part = message_part
            if part_index < match_count:
                combined_part += all_matches[part_index]
            if remaining_indices and part_index == remaining_indices[0]:
                combined_part += dyn_values
                try:
                    final_value = match_exp.sub(replace_exp, combined_part)
                except (re_error, IndexError) as e:
                    self.logger.error(exc_invalid_regex.format(match_exp.pattern + ' or expression ' + replace_exp, e))
                    return msg_as_string
                self.logger.debug('Found {}, replaced using {} in {}'.format(match_exp.pattern, replace_exp, combined_part))
                modified_message += final_value
                remaining_indices.pop(0)
            else:
                modified_message += combined_part

        return modified_message

########################################################################################################################
#  End CustomParameterHandler.py
########################################################################################################################

