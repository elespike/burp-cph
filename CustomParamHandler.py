########################################################################################################################
#  Begin CustomParameterHandler.py Imports
########################################################################################################################

from logging import (
    Formatter    ,
    INFO         ,
    StreamHandler,
    getLogger    ,
)
from re import (
    compile          ,
    error as re_error,
    search           ,
    sub              ,
)
from sys    import stdout
from urllib import quote

from CPH_Config  import MainTab
from burp        import IBurpExtender
from burp        import IHttpListener
from burp        import ISessionHandlingAction
from burp        import IContextMenuFactory
from javax.swing import JMenuItem

########################################################################################################################
#  End CustomParameterHandler.py Imports
########################################################################################################################

########################################################################################################################
#  Begin CustomParameterHandler.py
########################################################################################################################

class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction, IContextMenuFactory):
    def __init__(self):
        self._hostheader = 'Host: '
        self.messages_to_send = []
        self.final_macro_resp = ''

        self.logger = getLogger(__name__)
        self.initialize_logger()

    def initialize_logger(self):
        fmt='\n%(asctime)s:%(msecs)03d %(levelname)s: %(message)s'
        datefmt='%Y-%m-%d %H:%M:%S'
        formatter = Formatter(fmt=fmt, datefmt=datefmt)

        handler = StreamHandler(stream=stdout)
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(INFO)

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.maintab = MainTab(self)
        callbacks.setExtensionName('Custom Parameter Handler')
        callbacks.registerHttpListener(self)
        callbacks.registerSessionHandlingAction(self)
        callbacks.registerContextMenuFactory(self)
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
                or context == invocation.CONTEXT_PROXY_HISTORY \
                or context == invocation.CONTEXT_TARGET_SITE_MAP_TABLE \
                or context == invocation.CONTEXT_SEARCH_RESULTS:
            self.messages_to_send = invocation.getSelectedMessages()
            if len(self.messages_to_send):
                return [JMenuItem('Send to CPH', actionPerformed=self.send_to_cph)]
        else:
            return None

    def send_to_cph(self, e):
        self.maintab.add_config_tab(self.messages_to_send)

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
        tab.request = tab.param_handl_request_editor.getMessage()
        req_as_string = self.helpers.bytesToString(tab.request)
        req_info = self.helpers.analyzeRequest(tab.request)
        headers = req_info.getHeaders()

        # Update host header
        host = ''
        port = 80
        https = tab.https_chkbox.isSelected()
        if https:
            port = 443
        for header in headers:
            if header.startswith(self._hostheader):
                host = header.replace(self._hostheader, '')
                if ':' in host:
                    host, port = self.split_host_port(host)
        self.logger.debug('Host is: {}'.format(host))

        # Update cookies
        if tab.update_cookies_chkbox.isSelected():
            cookies = self.callbacks.getCookieJarContents()
            for cookie in cookies:
                cdom = cookie.getDomain()
                if host not in cdom:
                    continue
                self.logger.debug('Cookie domain is: {}'.format(cdom))
                cname = cookie.getName()
                for header in headers:
                    if header.startswith('Cookie: '):
                        self.logger.debug('Cookie header from derivation request:\n{}'.format(header))
                        if not header.endswith(';'):
                            header += ';'
                        match = search(r'[ ;]' + cname + r'=.+?[;\r]', header)
                        if match:
                            self.logger.debug('Cookie found in derivation request headers: {}'.format(cname))
                            cvalue = cookie.getValue()
                            self.logger.debug('Cookie value from Burp\'s jar: "{}"'.format(cvalue))
                            if cvalue:
                                exp = compile('({}=).+?([;\r])'.format(cname))
                                req_as_string = exp.sub('\g<1>{}\g<2>'.format(cvalue), req_as_string)
                                tab.request = self.helpers.stringToBytes(req_as_string)
                                tab.param_handl_request_editor.setMessage(tab.request, True)
                                self.logger.info('Cookie updated on tab "{}": {}={}'.format(
                                    tab.namepane_txtfield.getText(), cname, cvalue))

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
                tab.namepane_txtfield.getText(), host))
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
        requesturl = requestinfo.getUrl()
        if not self.callbacks.isInScope(requesturl):
            return
        req = messageInfo.getRequest()
        req_as_string = self.helpers.bytesToString(req)
        content_length_pattern = r'Content-Length: \d+\r\n'
        content_length_repl = 'Content-Length: {}\r\n'
        set_cache = False
        if messageIsRequest:
            for tab in self.maintab.get_config_tabs():
                if req == tab.request:
                    continue
                if tab.tabtitle.enable_chkbox.isSelected() and \
                        self.is_in_cph_scope(req_as_string, messageIsRequest, tab):
                    self.logger.info('Sending request to tab "{}" for modification'.format(tab.namepane_txtfield.getText()))
                    req_as_string = self.modify_message(tab, req_as_string)
                    # URL-encode the first line of the request in case it was modified
                    first_req_line_old = req_as_string.split('\r\n')[0]
                    self.logger.debug('first_req_line_old is:\n{}'.format(first_req_line_old))
                    first_req_line_old = first_req_line_old.split(' ')
                    first_req_line_new = '{} {} {}'.format(
                        first_req_line_old[0],
                        ''.join([quote(char, safe='/%+=?&') for char in '%20'.join(first_req_line_old[1:-1])]),
                        first_req_line_old[-1])
                    self.logger.debug('first_req_line_new is:\n{}'.format(first_req_line_new))
                    req_as_string = req_as_string.replace(' '.join(first_req_line_old), first_req_line_new)
                    self.logger.debug('Actual first line of request is:\n{}'.format(req_as_string.split('\r\n')[0]))
                    req = self.helpers.stringToBytes(req_as_string)

            requestinfo = self.helpers.analyzeRequest(req)
            content_length = len(req) - requestinfo.getBodyOffset()
            req_as_string = sub(content_length_pattern,
                                   content_length_repl.format(content_length),
                                   req_as_string,
                                   1)
            req = self.helpers.stringToBytes(req_as_string)
            messageInfo.setRequest(req)

            requestinfo = self.helpers.analyzeRequest(req)
            new_headers = requestinfo.getHeaders()
            httpsvc = messageInfo.getHttpService()
            port = httpsvc.getPort()
            for header in new_headers:
                if self._hostheader in header:
                    host = header.replace(self._hostheader, '')
                    if ':' in host:
                        host, port = self.split_host_port(host)
                    messageInfo.setHttpService(self.helpers.buildHttpService(
                        host, port, httpsvc.getProtocol()))
                    break
            self.logger.debug('Forwarding request to host "{}"'.format(messageInfo.getHttpService().getHost()))

            for tab in self.maintab.get_config_tabs():
                self.logger.debug(
                    'set_cache is {}, working on request for tab {}'.format(set_cache, tab.namepane_txtfield.getText()))
                if set_cache:
                    tab.param_handl_cached_req_viewer.setMessage(req, False)
                    self.logger.debug('Cached request viewer updated for tab {}!'.format(tab.namepane_txtfield.getText()))
                if self.is_in_cph_scope(req_as_string, messageIsRequest, tab, True):
                    tab.cached_request = req
                    set_cache = True
                    self.logger.debug('Cached request set for tab {}!'.format(tab.namepane_txtfield.getText()))
                else:
                    set_cache = False

        if not messageIsRequest:
            resp = messageInfo.getResponse()
            resp_as_string = self.helpers.bytesToString(resp)
            for tab in self.maintab.get_config_tabs():
                if tab.tabtitle.enable_chkbox.isSelected() and \
                        self.is_in_cph_scope(resp_as_string, messageIsRequest, tab):
                    self.logger.info('Sending response to tab "{}" for modification'.format(tab.namepane_txtfield.getText()))
                    resp_as_string = self.modify_message(tab, resp_as_string)
                    resp = self.helpers.stringToBytes(resp_as_string)

            responseinfo = self.helpers.analyzeResponse(resp)
            content_length = len(resp) - responseinfo.getBodyOffset()
            resp_as_string = sub(content_length_pattern,
                                    content_length_repl.format(content_length),
                                    resp_as_string,
                                    1)
            resp = self.helpers.stringToBytes(resp_as_string)
            messageInfo.setResponse(resp)

            for tab in self.maintab.get_config_tabs():
                self.logger.debug('set_cache is {}, working on response for tab {}'.format(set_cache,
                                                                               tab.namepane_txtfield.getText()))
                if set_cache:
                    tab.param_handl_cached_resp_viewer.setMessage(resp, False)
                    if not tab.param_handl_radio_extract_cached.isEnabled():
                        tab.param_handl_radio_extract_cached.setEnabled(True)
                    self.logger.debug('Cached response viewer updated, radio enabled for tab {}!'.format(
                        tab.namepane_txtfield.getText()))
                if self.is_in_cph_scope(req_as_string, True, tab, True):
                    tab.cached_response = resp
                    set_cache = True
                    self.logger.debug('Cached response set for tab {}!'.format(tab.namepane_txtfield.getText()))
                else:
                    set_cache = False

    def is_in_cph_scope(self, msg_as_string, is_request, tab, caching=False):
        rms_radio_type_requests_selected = tab.msg_mod_radio_req.isSelected()
        rms_radio_type_responses_selected = tab.msg_mod_radio_resp.isSelected()
        rms_radio_type_both_selected = tab.msg_mod_radio_both.isSelected()
        rms_radio_modifyall_selected = tab.msg_mod_radio_all.isSelected()
        rms_radio_modifymatch_selected = tab.msg_mod_radio_exp.isSelected()
        rms_field_modifymatch_txt, \
        rms_checkbox_modifymatch_regex = tab.get_exp_pane_values(tab.msg_mod_exp_pane_scope)

        if not caching:
            if is_request and (rms_radio_type_requests_selected or rms_radio_type_both_selected):
                self.logger.debug('is_request and (rms_radio_type_requests_selected or rms_radio_type_both_selected): {}'.format(
                    is_request and (rms_radio_type_requests_selected or rms_radio_type_both_selected)))
            elif not is_request and (rms_radio_type_responses_selected or rms_radio_type_both_selected):
                self.logger.debug(
                    'not is_request and (rms_radio_type_responses_selected or rms_radio_type_both_selected): {}'.format(
                        not is_request and (rms_radio_type_responses_selected or rms_radio_type_both_selected)))
            else:
                self.logger.debug('Returning False from is_in_cph_scope')
                return False

        if rms_radio_modifyall_selected:
            return True
        elif rms_radio_modifymatch_selected and rms_field_modifymatch_txt:
            if rms_checkbox_modifymatch_regex:
                regexp = compile(rms_field_modifymatch_txt)
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
        ph_radio_insert_selected = tab.param_handl_radio_insert.isSelected()
        ph_radio_replace_selected = tab.param_handl_radio_replace.isSelected()
        ph_field_matchnum_txt = tab.param_handl_txtfield_match_indices.getText()
        ph_field_matchtarget_txt, \
        ph_checkbox_matchtarget_regex = tab.get_exp_pane_values(tab.param_handl_exp_pane_target)
        ph_field_staticvalue_txt = tab.param_handl_txtfield_static_value.getText()
        ph_radio_extract_cached_selected = tab.param_handl_radio_extract_cached.isSelected()
        ph_radio_extract_single_selected = tab.param_handl_radio_extract_single.isSelected()
        ph_radio_extract_macro_selected = tab.param_handl_radio_extract_macro.isSelected()
        ph_field_extract_cached_txt, \
        ph_checkbox_extract_cached_regex = tab.get_exp_pane_values(tab.param_handl_exp_pane_extract_cached)
        ph_field_extract_single_txt, \
        ph_checkbox_extract_single_regex = tab.get_exp_pane_values(tab.param_handl_exp_pane_extract_single)
        ph_field_extract_macro_txt, \
        ph_checkbox_extract_macro_regex = tab.get_exp_pane_values(tab.param_handl_exp_pane_extract_macro)
        original_msg = msg_as_string
        match_value = ph_field_matchtarget_txt
        self.logger.debug('Initial match value: {}'.format(match_value))

        exc_search_for_exp = 'Error searching for expression {}. Details below:'
        if ph_checkbox_matchtarget_regex:
            match = None
            try:
                match = search(ph_field_matchtarget_txt, msg_as_string)
            except re_error:
                self.logger.exception(exc_search_for_exp.format(
                    ph_field_matchtarget_txt))
            if match:
                match_value = match.group(0)
                if match.groups():
                    match_value = match.group(1)
            self.logger.debug('Extracted match value using this expression: {}'.format(
                ph_field_matchtarget_txt))
            self.logger.debug('Match value is now: {}'.format(match_value))
        self.logger.debug('Final match value: {}'.format(match_value))

        if not match_value:
            self.logger.warning('No match found! Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()))
            return original_msg

        replace_value = ph_field_staticvalue_txt.replace('\n', '\r\n')
        self.logger.debug('Initial replace value: {}'.format(replace_value))

        match = None
        dbg_extracted_repl = 'Extracted replace value using this expression: {}'
        dbg_extract_repl_fail = 'Failed to extract replace value using this expression: {}'
        dbg_new_repl_val = 'Replace value is now: {}'
        if ph_radio_extract_cached_selected:
            try:
                match = search(ph_field_extract_cached_txt,
                                  self.helpers.bytesToString(tab.param_handl_cached_resp_viewer.getMessage()))
            except re_error:
                self.logger.exception(exc_search_for_exp.format(
                    ph_field_extract_cached_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                self.logger.debug(dbg_extracted_repl.format(ph_field_extract_cached_txt))
                self.logger.debug(dbg_new_repl_val.format(replace_value))
            else:
                self.logger.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_cached_txt))
        elif ph_radio_extract_single_selected:
            try:
                self.issue_request(tab)
                match = search(ph_field_extract_single_txt, self.helpers.bytesToString(tab.response))
            except re_error:
                self.logger.exception(exc_search_for_exp.format(
                    ph_field_extract_single_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                self.logger.debug(dbg_extracted_repl.format(ph_field_extract_single_txt))
                self.logger.debug(dbg_new_repl_val.format(replace_value))
            else:
                self.logger.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_single_txt))
        elif ph_radio_extract_macro_selected:
            try:
                match = search(ph_field_extract_macro_txt, self.final_macro_resp)
            except re_error:
                self.logger.exception(exc_search_for_exp.format(
                    ph_field_extract_macro_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                self.logger.debug(dbg_extracted_repl.format(ph_field_extract_macro_txt))
                self.logger.debug(dbg_new_repl_val.format(replace_value))
            else:
                self.logger.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_macro_txt))

        self.logger.debug('Final replace value: {}'.format(replace_value))
        self.logger.debug('Searching for "{}", inserting/replacing "{}"'.format(match_value, replace_value))

        match_count = original_msg.count(match_value)
        match_indices = ph_field_matchnum_txt.replace(' ', '').split(',')
        len_match_indices = len(match_indices)
        for i, v in enumerate(match_indices):
            if i == len_match_indices:
                break
            try:
                if ':' in v:
                    sliceindex = v.index(':')
                    start = int(v[:sliceindex])
                    end = int(v[sliceindex + 1:])
                    if start < 0:
                        start = match_count + start
                    if end < 0:
                        end = match_count + end
                    for match_index in range(start, end):
                        if match_index == start:
                            match_indices[i] = match_index
                        else:
                            match_indices.append(match_index)
                else:
                    match_index = int(v)
                    if match_index < 0:
                        match_index = match_count + match_index
                    match_indices[i] = match_index
            except ValueError:
                self.logger.exception('Invalid match index or slice detected on tab "{}". Ignoring. Details below:'.format(
                    tab.namepane_txtfield.getText()))
                continue

        self.logger.debug('Unfiltered match indices: {}'.format(match_indices))
        match_indices = sorted([m for m in match_indices if m < match_count])
        self.logger.debug('Filtered match indices: {}'.format(match_indices))

        modification_count = 0
        for match_index in match_indices:
            num = -1
            substr_index = -1
            try:
                while num < match_index:
                    substr_index = original_msg.index(match_value, substr_index + 1)
                    num += 1
            except ValueError:
                self.logger.exception('This should never have happened! Check the filtering mechanism.\n\t'
                          + 'Current tab: {}'.format(tab.namepane_txtfield.getText()))
                continue
            substr_index += (len(replace_value) - len(match_value)) * modification_count
            if ph_radio_insert_selected:
                insert_at = substr_index + (len(match_value) * (modification_count + 1))
                msg_as_string = msg_as_string[:insert_at] \
                                + replace_value \
                                + msg_as_string[insert_at:]
                modification_count += 1
                self.logger.info('Match index [{}]: inserted "{}" after "{}"'.format(
                    match_index, replace_value, match_value))
            elif ph_radio_replace_selected:
                msg_as_string = msg_as_string[:substr_index] \
                                + replace_value \
                                + msg_as_string[substr_index + len(match_value):]
                modification_count += 1
                self.logger.info('Match index [{}]: matched "{}", replaced with "{}"'.format(
                    match_index, match_value, replace_value))

        if modification_count == 0:
            self.logger.warning('No match found for "{}"! Skipping tab "{}".'.format(
                match_value, tab.namepane_txtfield.getText()))
            return original_msg

        return msg_as_string

########################################################################################################################
#  End CustomParameterHandler.py
########################################################################################################################
