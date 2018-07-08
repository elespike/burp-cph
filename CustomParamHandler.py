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
    compile as re_compile,
    error   as re_error  ,
    findall as re_findall,
    split   as re_split  ,
    search  as re_search ,
    sub     as re_sub    ,
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
        # TODO remove when host fwd stuff is done
        self._hostheader = 'Host: '
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
            self.logger.warning('Effective Modification Viewer not found! You may be using an outdated version of CPH!')

        while self.maintab.mainpane.getTabCount():
            # For some reason, the last tab isn't removed until the next loop,
            # hence the try/except block with just a continue. Thx, Java.
            try:
                self.maintab.mainpane.remove(
                    self.maintab.mainpane.getTabCount() - 1
                )
            except:
                continue

    # TODO probably remove this later
    @staticmethod
    def split_host_port(host_and_port):
        split_index = host_and_port.index(':')
        host = host_and_port[:split_index]
        try:
            port = int(host_and_port[split_index + 1:])
            return host, port
        except ValueError:
            self.logger.exception('Invalid port value detected; reverting to port 80. Details below:')
            return host, 80

    def issue_request(self, tab):
        tab.request   = tab.param_handl_request_editor.getMessage()
        req_as_string = self.helpers.bytesToString (tab.request)
        req_info      = self.helpers.analyzeRequest(tab.request)
        headers       = req_info.getHeaders()

        # TODO probably remove this after a host/port control is in place
        # Update host header
        host = ''
        port = 80
        https = tab.param_handl_https_chkbox.isSelected()
        if https:
            port = 443
        for header in headers:
            if header.startswith(self._hostheader):
                host = header.replace(self._hostheader, '')
                if ':' in host:
                    host, port = self.split_host_port(host)
        self.logger.debug('Host: {}'.format(host))

        # Update cookies
        if tab.param_handl_update_cookies_chkbox.isSelected():
            cookies = self.callbacks.getCookieJarContents()
            for cookie in cookies:
                cdom = cookie.getDomain()
                if host not in cdom:
                    continue
                self.logger.debug('Cookie domain: {}'.format(cdom))
                cname = cookie.getName()
                for header in headers:
                    if header.startswith('Cookie: '):
                        self.logger.debug('Cookie header from derivation request:\n{}'.format(header))
                        if not header.endswith(';'):
                            header += ';'
                        match = re_search(r'[ ;]' + cname + r'=.+?[;\r]', header)
                        if match:
                            self.logger.debug('Cookie found in derivation request headers: {}'.format(cname))
                            cvalue = cookie.getValue()
                            self.logger.debug('Cookie value from Burp\'s jar: "{}"'.format(cvalue))
                            if cvalue:
                                exp = re_compile('({}=).+?([;\r])'.format(cname))
                                req_as_string = exp.sub('\g<1>{}\g<2>'.format(cvalue), req_as_string)
                                tab.request = self.helpers.stringToBytes(req_as_string)
                                tab.param_handl_request_editor.setMessage(tab.request, True)
                                self.logger.info('Cookie updated on tab "{}": {}={}'.format(
                                    tab.namepane_txtfield.getText(),
                                    cname,
                                    cvalue
                                ))

        try:
            httpsvc = self.helpers.buildHttpService(host, port, https)
            resp = self.callbacks.makeHttpRequest(httpsvc, tab.request).getResponse()
            self.logger.debug('Issued configured request from tab "{}" to host "{}"'.format(
                tab.namepane_txtfield.getText(), httpsvc.getHost()))
            if resp:
                tab.param_handl_response_editor.setMessage(resp, False)
                tab.response = resp
                self.logger.debug('Got response!')
        # Generic except because misc. Java exceptions might occur.
        except:
            self.logger.exception('Error issuing configured request from tab "{}" to host "{}"'.format(
                tab.namepane_txtfield.getText(),
                host
            ))
            tab.response = self.helpers.stringToBytes('Error! See extension output for details.')
            tab.param_handl_response_editor.setMessage(tab.response, False)

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
        req = messageInfo.getRequest()
        req_as_string = self.helpers.bytesToString(req)
        content_length_pattern = r'Content-Length: \d+\r\n'
        content_length_repl    =  'Content-Length: {}\r\n'
        set_cache = False
        if messageIsRequest:
            for tab in self.maintab.get_config_tabs():
                if req == tab.request:
                    continue
                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(req_as_string, messageIsRequest, tab):
                    self.logger.info('Sending request to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))
                    modified_request = self.modify_message(tab, req_as_string)
                    if req_as_string != modified_request:
                        if tab.param_handl_auto_encode_chkbox.isSelected():
                            # URL-encode the first line of the request, since it was modified
                            first_req_line_old = modified_request.split('\r\n')[0]
                            self.logger.debug('first_req_line_old:\n{}'.format(first_req_line_old))
                            first_req_line_old = first_req_line_old.split(' ')
                            first_req_line_new = '{} {} {}'.format(
                                first_req_line_old[0],
                                ''.join([quote(char, safe='/%+=?&') for char in '%20'.join(first_req_line_old[1:-1])]),
                                first_req_line_old[-1]
                            )
                            self.logger.debug('first_req_line_new:\n{}'.format(first_req_line_new))
                            modified_request = modified_request.replace(
                                ' '.join(first_req_line_old),
                                first_req_line_new
                            )
                        tab.emv_tab.add_table_row(dt.now().time(), True, req_as_string, modified_request)
                        req_as_string = modified_request
                        self.logger.debug('Resulting first line of request:\n{}'.format(
                            req_as_string.split('\r\n')[0]
                        ))
                        req = self.helpers.stringToBytes(req_as_string)

            requestinfo    = self.helpers.analyzeRequest(req)
            content_length = len(req) - requestinfo.getBodyOffset()
            req_as_string  = re_sub(
                content_length_pattern,
                content_length_repl.format(content_length),
                req_as_string,
                1
            )
            req = self.helpers.stringToBytes(req_as_string)
            messageInfo.setRequest(req)

            # TODO probably remove this after the fwd control is in place
            requestinfo = self.helpers.analyzeRequest(req)
            new_headers = requestinfo.getHeaders()
            httpsvc = messageInfo.getHttpService()
            port = httpsvc.getPort()
            for header in new_headers:
                if self._hostheader in header:
                    host = header.replace(self._hostheader, '')
                    if ':' in host:
                        host, port = self.split_host_port(host)
                    messageInfo.setHttpService(self.helpers.buildHttpService(host, port, httpsvc.getProtocol()))
                    break
            self.logger.debug('Forwarding request to host "{}"'.format(messageInfo.getHttpService().getHost()))

        if not messageIsRequest:
            resp = messageInfo.getResponse()
            resp_as_string = self.helpers.bytesToString(resp)
            for tab in self.maintab.get_config_tabs():
                if tab.tabtitle_pane.enable_chkbox.isSelected() \
                and self.is_in_cph_scope(resp_as_string, messageIsRequest, tab):
                    self.logger.info('Sending response to tab "{}" for modification'.format(
                        tab.namepane_txtfield.getText()
                    ))
                    modified_response = self.modify_message(tab, resp_as_string)
                    if resp_as_string != modified_response:
                        tab.emv_tab.add_table_row(dt.now().time(), False, resp_as_string, modified_response)
                        resp_as_string = modified_response
                    resp = self.helpers.stringToBytes(resp_as_string)

            responseinfo   = self.helpers.analyzeResponse(resp)
            content_length = len(resp) - responseinfo.getBodyOffset()
            resp_as_string = re_sub(
                content_length_pattern,
                content_length_repl.format(content_length),
                resp_as_string,
                1
            )
            resp = self.helpers.stringToBytes(resp_as_string)
            messageInfo.setResponse(resp)

            for working_tab in self.maintab.get_config_tabs():
                selected_item = working_tab.param_handl_combo_cached.getSelectedItem()
                working_tab.param_handl_combo_cached.removeAllItems()
                if self.is_in_cph_scope(req_as_string , True , working_tab)\
                or self.is_in_cph_scope(resp_as_string, False, working_tab):
                    working_tab.cached_request  = req
                    working_tab.cached_response = resp
                    self.logger.debug('Messages cached for tab {}!'.format(
                        working_tab.namepane_txtfield.getText()
                    ))
                for previous_tab in self.maintab.get_config_tabs():
                    if working_tab == previous_tab:
                        break
                    if previous_tab.cached_request is None or previous_tab.cached_response is None:
                        continue
                    empty_req, empty_resp = previous_tab.initialize_req_resp()
                    if previous_tab.cached_request == empty_req or previous_tab.cached_response == empty_resp:
                        continue
                    item = previous_tab.namepane_txtfield.getText()
                    working_tab.param_handl_combo_cached.addItem(item)
                    if item == selected_item:
                        working_tab.param_handl_combo_cached.setSelectedItem(item)

    def is_in_cph_scope(self, msg_as_string, is_request, tab):
        rms_scope_all  = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_ALL
        rms_scope_some = tab.msg_mod_combo_scope.getSelectedItem() == tab.MSG_MOD_COMBO_SCOPE_SOME

        rms_type_requests  = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_REQ
        rms_type_responses = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_RESP
        rms_type_both      = tab.msg_mod_combo_type.getSelectedItem() == tab.MSG_MOD_COMBO_TYPE_BOTH

        rms_field_modifymatch_txt = tab.get_exp_pane_component(tab.msg_mod_exp_pane_scope, tab.TXT_FIELD_INDEX).getText()

        if is_request and (rms_type_requests or rms_type_both):
            pass
        elif not is_request and (rms_type_responses or rms_type_both):
            pass
        else:
            self.logger.debug('Preliminary scope check negative!')
            return False

        if rms_scope_all:
            return True
        elif rms_scope_some and rms_field_modifymatch_txt:
            if rms_checkbox_modifymatch_regex:
                regexp = re_compile(rms_field_modifymatch_txt)
                if regexp.search(msg_as_string):
                    return True
            else:
                if rms_field_modifymatch_txt in msg_as_string:
                    return True
        else:
            self.logger.warning('Scope restriction is active but no expression was specified. Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()))
        return False

    def modify_message(self, tab, msg_as_string):
        ph_field_matchnum_txt    = tab.param_handl_txtfield_match_indices .getText()

        ph_field_matchtarget_txt    = tab.get_exp_pane_component(tab.param_handl_exp_pane_target        , tab.TXT_FIELD_INDEX).getText()
        ph_field_staticvalue_txt    = tab.get_exp_pane_component(tab.param_handl_exp_pane_extract_static, tab.TXT_FIELD_INDEX).getText()
        ph_field_extract_single_txt = tab.get_exp_pane_component(tab.param_handl_exp_pane_extract_single, tab.TXT_FIELD_INDEX).getText()
        ph_field_extract_macro_txt  = tab.get_exp_pane_component(tab.param_handl_exp_pane_extract_macro , tab.TXT_FIELD_INDEX).getText()
        ph_field_extract_cached_txt = tab.get_exp_pane_component(tab.param_handl_exp_pane_extract_cached, tab.TXT_FIELD_INDEX).getText()

        if not ph_field_matchtarget_txt:
            self.logger.warning(
                'No match expression specified! Skipping tab "{}".'.format(
                    tab.namepane_txtfield.getText()
                )
            )
            return msg_as_string

        exc_invalid_regex = 'Skipping tab "{}" due to invalid regular expression: {{}}'.format(
            tab.namepane_txtfield.getText()
        )

        try:
            match_exp = re_compile(ph_field_matchtarget_txt)
        except re_error:
            self.logger.exception(exc_invalid_regex.format(ph_field_matchtarget_txt))
            return msg_as_string

        # The following code does not remove support for groups,
        # as the original expression will be used for actual replacements.
        # We simply need an expression without capturing groups to feed into re.findall(),
        # which enables the logic for granular control over which match indices to target.

        # Removing named groups to normalize capturing groups.
        findall_exp = re_sub('\?P<.+?>', '', ph_field_matchtarget_txt)
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
                    ph_field_matchtarget_txt
                )
            )
            return msg_as_string

        matches = list()
        replace_value = ph_field_staticvalue_txt

        find_exp, target_txt = '', ''
        if tab.param_handl_combo_extract.getSelectedItem() == tab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
            find_exp, target_txt = ph_field_extract_cached_txt, tab.param_handl_cached_resp_viewer.getMessage()
            target_txt = self.helpers.bytesToString(target_txt)

        elif tab.param_handl_combo_extract.getSelectedItem() == tab.PARAM_HANDL_COMBO_EXTRACT_SINGLE:
            self.issue_request(tab)
            find_exp, target_txt = ph_field_extract_single_txt, self.helpers.bytesToString(tab.response)

        elif tab.param_handl_combo_extract.getSelectedItem() == tab.PARAM_HANDL_COMBO_EXTRACT_MACRO:
            find_exp, target_txt = ph_field_extract_macro_txt, self.final_macro_resp

        if find_exp and target_txt:
            try:
                matches = re_findall(find_exp, target_txt)
            except re_error:
                self.logger.exception(exc_invalid_regex.format(ph_field_extract_macro_txt))
                return msg_as_string

            if matches:
                # Converting into a set to ignore duplicates.
                if len(set(matches)) > 1:
                    # TODO the message:
                    self.logger.warning('Ambiguous, skipping tab')
                    return msg_as_string
                # Joining in case multiple groups were used.
                replace_value = ''.join(matches[0])
            else:
                # TODO no replacement value found
                self.logger.warning('not found yo, skipping tab')
                return msg_as_string

        self.logger.debug('replace_value: {}'.format(replace_value))

        subsets = ph_field_matchnum_txt.replace(' ', '').split(',')
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
            except ValueError:
                self.logger.exception(
                    'Invalid match index or slice detected on tab "{}". Ignoring. Details below:'.format(
                        tab.namepane_txtfield.getText()
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
                if tab.param_handl_combo_action.getSelectedItem() == tab.PARAM_HANDL_COMBO_ACTION_REPLACE:
                    final_value = match_exp.sub(replace_value, combined_part)
                else: # append
                    final_value = combined_part + replace_value
                self.logger.debug('Modification: {}'.format(final_value))
                modified_message += final_value
                remaining_indices.pop(0)
            else:
                modified_message += combined_part

        return modified_message

########################################################################################################################
#  End CustomParameterHandler.py
########################################################################################################################

