import re
import logging
from sys import stdout

from CPH_Config import MainTab
from burp import IBurpExtender
from burp import IHttpListener
from burp import ISessionHandlingAction
from burp import IContextMenuFactory
from javax.swing import JMenuItem


class BurpExtender(IBurpExtender, IHttpListener, ISessionHandlingAction, IContextMenuFactory):
    def __init__(self):
        self._hostheader = 'Host: '
        logging.basicConfig(
            level=logging.DEBUG,
            format='\r\n%(asctime)s:%(msecs)03d %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            stream=stdout)
        self.messages_to_send = []
        self.final_macro_resp = ''

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
            logging.error('No macro found, or macro is empty!')
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
            logging.exception('Invalid port value detected; reverting to port 80. Details below:')
            return host, 80

    def issue_request(self, tab):
        tab.request = tab.param_handl_request_editor.getMessage()
        req_as_string = self.helpers.bytesToString(tab.request)
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            cname = cookie.getName()
            if cname in req_as_string:
                cvalue = cookie.getValue()
                match = re.search(cname + r'=(.+)[;\r]', req_as_string)
                if match:
                    req_as_string = req_as_string.replace(match.group(1), cvalue)
                    tab.request = self.helpers.stringToBytes(req_as_string)
                    tab.param_handl_request_editor.setMessage(tab.request, True)

        info = self.helpers.analyzeRequest(tab.request)
        headers = info.getHeaders()
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
        httpsvc = self.helpers.buildHttpService(host, port, https)
        try:
            resp = self.callbacks.makeHttpRequest(httpsvc, tab.request).getResponse()
            logging.debug('Issued configured request from tab "{}" to host "{}"'.format(
                tab.namepane_txtfield.getText(), httpsvc.getHost()))
            if resp:
                tab.param_handl_response_editor.setMessage(resp, False)
                tab.response = resp
                logging.debug('Got response!')
        # todo: figure out if this needs to be a generic except or if there's a way to narrow it down
        except:
            logging.exception('Error issuing configured request from tab "{}" to host "{}"'.format(
                tab.namepane_txtfield.getText(), httpsvc.getHost()))
            tab.response = self.helpers.stringToBytes('Error! See extension output for details.')
            tab.param_handl_response_editor.setMessage(tab.response, False)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        dbg_skip_tool = 'Skipping message received from {} on account of global tool scope options.'
        if toolFlag == self.callbacks.TOOL_PROXY:
            if not self.maintab.options_tab.chkbox_proxy.isSelected():
                logging.debug(dbg_skip_tool.format('Proxy'))
                return
        elif toolFlag == self.callbacks.TOOL_TARGET:
            if not self.maintab.options_tab.chkbox_target.isSelected():
                logging.debug(dbg_skip_tool.format('Target'))
                return
        elif toolFlag == self.callbacks.TOOL_SPIDER:
            if not self.maintab.options_tab.chkbox_spider.isSelected():
                logging.debug(dbg_skip_tool.format('Spider'))
                return
        elif toolFlag == self.callbacks.TOOL_REPEATER:
            if not self.maintab.options_tab.chkbox_repeater.isSelected():
                logging.debug(dbg_skip_tool.format('Repeater'))
                return
        elif toolFlag == self.callbacks.TOOL_SEQUENCER:
            if not self.maintab.options_tab.chkbox_sequencer.isSelected():
                logging.debug(dbg_skip_tool.format('Sequencer'))
                return
        elif toolFlag == self.callbacks.TOOL_INTRUDER:
            if not self.maintab.options_tab.chkbox_intruder.isSelected():
                logging.debug(dbg_skip_tool.format('Intruder'))
                return
        elif toolFlag == self.callbacks.TOOL_SCANNER:
            if not self.maintab.options_tab.chkbox_scanner.isSelected():
                logging.debug(dbg_skip_tool.format('Scanner'))
                return
        elif toolFlag == self.callbacks.TOOL_EXTENDER:
            if not self.maintab.options_tab.chkbox_extender.isSelected():
                logging.debug(dbg_skip_tool.format('Extender'))
                return
        else:
            logging.debug('Skipping message received from unsupported Burp tool.')
            return

        requestinfo = self.helpers.analyzeRequest(messageInfo)
        requesturl = requestinfo.getUrl()
        if not self.callbacks.isInScope(requesturl):
            return
        req = messageInfo.getRequest()
        req_as_string = self.helpers.bytesToString(req)
        set_cache = False

        if messageIsRequest:
            for tab in self.maintab.get_config_tabs():
                if req == tab.request:
                    continue
                if tab.tabtitle.enable_chkbox.isSelected() and self.is_in_cph_scope(req_as_string, tab):
                    req_as_string = self.modify_request(tab, req_as_string)
                    # URL-encode the first line of the request in case it was modified
                    first_req_line_old = req_as_string.split('\r\n')[0].split(' ')
                    first_req_line_new = '{} {} {}'.format(
                        first_req_line_old[0],
                        '+'.join([self.helpers.urlEncode(chars) for chars in first_req_line_old[1:-1]]),
                        first_req_line_old[-1])
                    req_as_string = req_as_string.replace(''.join(first_req_line_old), first_req_line_new)
                    req = self.helpers.stringToBytes(req_as_string)

            for tab in self.maintab.get_config_tabs():
                if set_cache:
                    tab.param_handl_cached_req_viewer.setMessage(req, False)
                if self.is_in_cph_scope(req_as_string, tab):
                    tab.cached_request = req
                    set_cache = True
                else:
                    set_cache = False

            messageInfo.setRequest(req)
            new_headers = self.helpers.analyzeRequest(messageInfo).getHeaders()
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
            logging.debug('Forwarding request to host "{}"'.format(messageInfo.getHttpService().getHost()))

        if not messageIsRequest:
            resp = messageInfo.getResponse()
            for tab in self.maintab.get_config_tabs():
                if set_cache:
                    tab.param_handl_cached_resp_viewer.setMessage(resp, False)
                    if not tab.param_handl_radio_extract_cached.isEnabled():
                        tab.param_handl_radio_extract_cached.setEnabled(True)
                if self.is_in_cph_scope(req_as_string, tab):
                    tab.cached_response = resp
                    set_cache = True
                else:
                    set_cache = False

    @staticmethod
    def is_in_cph_scope(req_as_string, tab):
        rms_radio_modifyall_selected = tab.req_mod_radio_all.isSelected()
        rms_radio_modifymatch_selected = tab.req_mod_radio_exp.isSelected()
        rms_field_modifymatch_txt, \
        rms_checkbox_modifymatch_regex = tab.get_exp_pane_values(tab.req_mod_exp_pane_scope)
        if rms_radio_modifyall_selected:
            return True
        elif rms_radio_modifymatch_selected and rms_field_modifymatch_txt:
            if rms_checkbox_modifymatch_regex:
                regexp = re.compile(rms_field_modifymatch_txt)
                if regexp.search(req_as_string):
                    return True
            else:
                if rms_field_modifymatch_txt in req_as_string:
                    return True
        else:
            logging.warning('Scope restriction is active but no expression was specified. Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()))
        return False

    def modify_request(self, tab, req_as_string):
        logging.info('Processing tab "{}"'.format(tab.namepane_txtfield.getText()))
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

        original_req = req_as_string
        match_value = ph_field_matchtarget_txt
        logging.debug('Initial match value: {}'.format(match_value))

        exc_search_for_exp = 'Error searching for expression {}. Details below:'
        if ph_checkbox_matchtarget_regex:
            match = None
            try:
                match = re.search(ph_field_matchtarget_txt, req_as_string)
            except re.error:
                logging.exception(exc_search_for_exp.format(
                    ph_field_matchtarget_txt))
            if match:
                match_value = match.group(0)
                if match.groups():
                    match_value = match.group(1)
            logging.debug('Extracted match value using this expression: {}'.format(
                ph_field_matchtarget_txt))
            logging.debug('Match value is now: {}'.format(match_value))
        logging.debug('Final match value: {}'.format(match_value))

        if not match_value:
            logging.warning('No match found! Skipping tab "{}".'.format(
                tab.namepane_txtfield.getText()))
            return original_req

        replace_value = ph_field_staticvalue_txt
        logging.debug('Initial replace value: {}'.format(replace_value))

        match = None
        dbg_extracted_repl = 'Extracted replace value using this expression: {}'
        dbg_extract_repl_fail = 'Failed to extract replace value using this expression: {}'
        dbg_new_repl_val = 'Replace value is now: {}'
        if ph_radio_extract_cached_selected:
            try:
                match = re.search(ph_field_extract_cached_txt,
                                  self.helpers.bytesToString(tab.param_handl_cached_resp_viewer.getMessage()))
            except re.error:
                logging.exception(exc_search_for_exp.format(
                    ph_field_extract_cached_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                logging.debug(dbg_extracted_repl.format(ph_field_extract_single_txt))
                logging.debug(dbg_new_repl_val.format(replace_value))
            else:
                logging.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_cached_txt))
        elif ph_radio_extract_single_selected:
            try:
                self.issue_request(tab)
                match = re.search(ph_field_extract_single_txt, self.helpers.bytesToString(tab.response))
            except re.error:
                logging.exception(exc_search_for_exp.format(
                    ph_field_extract_single_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                logging.debug(dbg_extracted_repl.format(ph_field_extract_single_txt))
                logging.debug(dbg_new_repl_val.format(replace_value))
            else:
                logging.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_single_txt))
        elif ph_radio_extract_macro_selected:
            try:
                match = re.search(ph_field_extract_macro_txt, self.final_macro_resp)
            except re.error:
                logging.exception(exc_search_for_exp.format(
                    ph_field_extract_macro_txt))
            if match:
                replace_value = match.group(0)
                if match.groups():
                    replace_value = match.group(1)
                logging.debug(dbg_extracted_repl.format(ph_field_extract_macro_txt))
                logging.debug(dbg_new_repl_val.format(replace_value))
            else:
                logging.debug(dbg_extract_repl_fail.format(
                    ph_field_extract_macro_txt))

        logging.debug('Final replace value: {}'.format(replace_value))
        logging.debug('Searching for "{}", inserting/replacing "{}"'.format(match_value, replace_value))

        match_count = original_req.count(match_value)
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
                logging.exception('Invalid match index or slice detected on tab "{}". Ignoring. Details below:'.format(
                    tab.namepane_txtfield.getText()))
                continue

        logging.debug('Unfiltered match indices: {}'.format(match_indices))
        match_indices = sorted([m for m in match_indices if m < match_count])
        logging.debug('Filtered match indices: {}'.format(match_indices))

        modification_count = 0
        for match_index in match_indices:
            num = -1
            substr_index = -1
            try:
                while num < match_index:
                    substr_index = original_req.index(match_value, substr_index + 1)
                    num += 1
            except ValueError:
                logging.exception('This should never have happened! Check the filtering mechanism.\r\n\t'
                                  + 'Current tab: {}'.format(tab.namepane_txtfield.getText()))
                continue
            substr_index += (len(replace_value) - len(match_value)) * modification_count
            if ph_radio_insert_selected:
                insert_at = substr_index + (len(match_value) * (modification_count + 1))
                req_as_string = req_as_string[:insert_at] \
                                + replace_value \
                                + req_as_string[insert_at:]
                modification_count += 1
                logging.info('Match index [{}]: inserted "{}" after "{}"'.format(
                    match_index, replace_value, match_value))
            elif ph_radio_replace_selected:
                req_as_string = req_as_string[:substr_index] \
                                + replace_value \
                                + req_as_string[substr_index + len(match_value):]
                modification_count += 1
                logging.info('Match index [{}]: matched "{}", replaced with "{}"'.format(
                    match_index, match_value, replace_value))

        if modification_count == 0:
            logging.warning('No match found for "{}"! Skipping tab "{}".'.format(
                match_value, tab.namepane_txtfield.getText()))
            return original_req

        return req_as_string
