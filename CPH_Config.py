from pickle import dump, load
from thread import start_new_thread
from logging import DEBUG, ERROR, INFO, WARNING, getLevelName
from webbrowser import open_new_tab as browser_open

import quickstart
from burp import ITab
from javax.swing import \
    BorderFactory, \
    ButtonGroup, \
    JButton, \
    JCheckBox, \
    JFileChooser, \
    JLabel, \
    JOptionPane, \
    JPanel, \
    JRadioButton, \
    JScrollPane, \
    JSeparator, \
    JSpinner, \
    JSplitPane, \
    JTabbedPane, \
    JTextField, \
    SpinnerNumberModel
from javax.swing.event import ChangeListener
from java.awt.event import \
    ActionListener, \
    KeyListener, \
    MouseAdapter
from java.awt import \
    CardLayout, \
    Color, \
    FlowLayout, \
    GridBagConstraints, \
    GridBagLayout, \
    Insets, \
    Font


class MainTab(ITab, ChangeListener):
    mainpane = JTabbedPane()

    def __init__(self, cph):
        MainTab.mainpane.addChangeListener(self)
        self._cph = cph
        self.options_tab = OptionsTab(cph)
        self.mainpane.add('Options', self.options_tab)
        self._add_sign = unichr(0x002b)  # addition sign
        self.mainpane.add(self._add_sign, JPanel())

    @staticmethod
    def getTabCaption():
        return 'CPH Config'

    def getUiComponent(self):
        return self.mainpane

    def add_config_tab(self, messages):
        for message in messages:
            ConfigTab(self._cph, message)

    def get_config_tabs(self):
        components = self.mainpane.getComponents()
        for i in range(len(components)):
            for tab in components:
                if isinstance(tab, ConfigTab) and i == self.mainpane.indexOfComponent(tab):
                    yield tab

    def stateChanged(self, e):
        if e.getSource() == self.mainpane:
            index = self.mainpane.getSelectedIndex()
            if hasattr(self, '_add_sign') and self.mainpane.getTitleAt(index) == self._add_sign:
                self.mainpane.setSelectedIndex(0)
                ConfigTab(self._cph)


class SubTab(JScrollPane, ActionListener):
    INSETS = Insets(2, 4, 2, 4)

    def __init__(self, cph):
        self._cph = cph
        self._main_tab_pane = JPanel(GridBagLayout())
        self.setViewportView(self._main_tab_pane)
        self.getVerticalScrollBar().setUnitIncrement(16)

    @staticmethod
    def create_blank_space():
        return JLabel(' ')

    @staticmethod
    def create_empty_button(button):
        button.setOpaque(False)
        button.setFocusable(False)
        button.setContentAreaFilled(False)
        button.setBorderPainted(False)

    @staticmethod
    def set_title_font(label):
        font = Font(Font.SANS_SERIF, Font.BOLD, 14)
        label.setFont(font)
        return label

    def initialize_constraints(self):
        constraints = GridBagConstraints()
        constraints.weightx = 1
        constraints.insets = self.INSETS
        constraints.fill = GridBagConstraints.HORIZONTAL
        constraints.gridx = 0
        constraints.gridy = 0
        return constraints

    @staticmethod
    def get_exp_pane_values(pane):
        """
        Expression panes are JPanels that have been uniformly created with 2 components:
        Component 0 is a text field
        Component 1 is a checkbox
        """
        return pane.getComponent(0).getText(), pane.getComponent(1).isSelected()

    @staticmethod
    def set_exp_pane_values(pane, text, check):
        pane.getComponent(0).setText(text)
        pane.getComponent(1).setSelected(check)

    @staticmethod
    def show_card(cardpanel, label):
        cl = cardpanel.getLayout()
        cl.show(cardpanel, label)


class OptionsTab(SubTab, ChangeListener):
    DOCS_URL = 'https://github.com/elespike/burp-cph/wiki'
    BTN_DOCS_LBL = 'View full guide'
    BTN_QUICKSAVE_LBL = 'Quicksave'
    BTN_QUICKLOAD_LBL = 'Quickload'
    BTN_EXPORTCONFIG_LBL = 'Export Config'
    BTN_IMPORTCONFIG_LBL = 'Import Config'
    CHKBOX_PANE_LBL = 'Tool scope settings'
    VERBOSITY_LBL = 'Verbosity level:'
    QUICKSTART_PANE_LBL = 'Quickstart guide'

    configname_tab_names = 'tab_names'
    configname_enabled = 'enabled'
    configname_modify_type_requests = 'modify_type_requests'
    configname_modify_type_responses = 'modify_type_responses'
    configname_modify_type_both = 'modify_type_both'
    configname_modify_all = 'modify_all'
    configname_modify_match = 'modify_match'
    configname_modify_exp = 'modify_exp'
    configname_modify_exp_regex = 'modify_exp_regex'
    configname_insert = 'insert'
    configname_replace = 'replace'
    configname_match_indices = 'match_indices'
    configname_match_value = 'match_value'
    configname_match_value_regex = 'match_value_regex'
    configname_static = 'static'
    configname_cached = 'cached'
    configname_single = 'single'
    configname_macro = 'macro'
    configname_static_value = 'static_value'
    configname_cached_value = 'cached_value'
    configname_cached_regex = 'cached_regex'
    configname_single_value = 'single_value'
    configname_single_regex = 'single_regex'
    configname_https = 'https'
    configname_update_cookies = 'update_cookies'
    configname_single_request = 'single_request'
    configname_single_response = 'single_response'
    configname_macro_value = 'macro_value'
    configname_macro_regex = 'macro_regex'

    def __init__(self, cph):
        SubTab.__init__(self, cph)
        self.tab_names = []

        btn_docs = JButton(self.BTN_DOCS_LBL)
        btn_docs.addActionListener(self)
        btn_quicksave = JButton(self.BTN_QUICKSAVE_LBL)
        btn_quicksave.addActionListener(self)
        btn_quickload = JButton(self.BTN_QUICKLOAD_LBL)
        btn_quickload.addActionListener(self)
        btn_exportconfig = JButton(self.BTN_EXPORTCONFIG_LBL)
        btn_exportconfig.addActionListener(self)
        btn_importconfig = JButton(self.BTN_IMPORTCONFIG_LBL)
        btn_importconfig.addActionListener(self)

        err, warn, info, dbg = 1, 2, 3, 4
        self.verbosity_translator = {
            err: ERROR,
            warn: WARNING,
            info: INFO,
            dbg: DEBUG}
        self.verbosity_level_lbl = JLabel(getLevelName(INFO))
        self.verbosity_spinner = JSpinner(SpinnerNumberModel(info, err, dbg, 1))
        self.verbosity_spinner.addChangeListener(self)

        verbosity_pane = JPanel(FlowLayout(FlowLayout.CENTER))
        verbosity_pane.add(JLabel(self.VERBOSITY_LBL))
        verbosity_pane.add(self.verbosity_spinner)
        verbosity_pane.add(self.verbosity_level_lbl)

        btn_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        constraints.gridwidth = 2
        btn_pane.add(self.create_blank_space(), constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        btn_pane.add(verbosity_pane, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_docs, constraints)
        constraints.gridy = 2
        constraints.gridx = 0
        btn_pane.add(btn_quicksave, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_exportconfig, constraints)
        constraints.gridy = 3
        constraints.gridx = 0
        btn_pane.add(btn_quickload, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_importconfig, constraints)

        self.chkbox_proxy = JCheckBox('Proxy', True)
        self.chkbox_target = JCheckBox('Target', False)
        self.chkbox_spider = JCheckBox('Spider', False)
        self.chkbox_repeater = JCheckBox('Repeater', True)
        self.chkbox_sequencer = JCheckBox('Sequencer', False)
        self.chkbox_intruder = JCheckBox('Intruder', False)
        self.chkbox_scanner = JCheckBox('Scanner', False)
        self.chkbox_extender = JCheckBox('Extender', False)

        chkbox_pane = JPanel(GridBagLayout())
        chkbox_pane.setBorder(BorderFactory.createTitledBorder(self.CHKBOX_PANE_LBL))
        chkbox_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        constraints = self.initialize_constraints()
        chkbox_pane.add(self.chkbox_proxy, constraints)
        constraints.gridy = 1
        chkbox_pane.add(self.chkbox_target, constraints)
        constraints.gridy = 2
        chkbox_pane.add(self.chkbox_spider, constraints)
        constraints.gridy = 3
        chkbox_pane.add(self.chkbox_repeater, constraints)
        constraints.gridx = 1
        constraints.gridy = 0
        chkbox_pane.add(self.chkbox_sequencer, constraints)
        constraints.gridy = 1
        chkbox_pane.add(self.chkbox_intruder, constraints)
        constraints.gridy = 2
        chkbox_pane.add(self.chkbox_scanner, constraints)
        constraints.gridy = 3
        chkbox_pane.add(self.chkbox_extender, constraints)

        quickstart_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        quickstart_pane.setBorder(BorderFactory.createTitledBorder(self.QUICKSTART_PANE_LBL))
        quickstart_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        quickstart_text_lbl = JLabel(quickstart.text)
        quickstart_text_lbl.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))
        quickstart_pane.add(quickstart_text_lbl)

        constraints = self.initialize_constraints()
        constraints.anchor = GridBagConstraints.FIRST_LINE_START
        constraints.weighty = 0.05
        constraints.gridwidth = 2
        self._main_tab_pane.add(self.create_blank_space(), constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        self._main_tab_pane.add(btn_pane, constraints)
        constraints.gridx = 1
        self._main_tab_pane.add(chkbox_pane, constraints)
        constraints.gridx = 2
        self._main_tab_pane.add(self.create_blank_space(), constraints)
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 2
        self._main_tab_pane.add(quickstart_pane, constraints)

    def stateChanged(self, e):
        if e.getSource() == self.verbosity_spinner:
            level = self.verbosity_translator[self.verbosity_spinner.getValue()]
            self._cph.set_logging_level(level)
            self.verbosity_level_lbl.setText(getLevelName(level))

    @staticmethod
    def set_tab_name(tab, tab_name):
        tab.namepane_txtfield.tab_label.setText(tab_name)
        tab.namepane_txtfield.setText(tab_name)

    def set_tab_values_from_quickload(self, tab, tab_name):
        self.set_tab_name(tab, tab_name)
        tab_name += '|'
        tab.tabtitle.enable_chkbox.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_enabled) == 'True')
        tab.msg_mod_radio_req.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_type_requests) == 'True')
        tab.msg_mod_radio_resp.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_type_responses) == 'True')
        tab.msg_mod_radio_both.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_type_both) == 'True')
        tab.msg_mod_radio_all.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_all) == 'True')
        if tab.msg_mod_radio_all.isSelected():
            tab.flip_msg_mod_controls(False)
        tab.msg_mod_radio_exp.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_match) == 'True')
        if tab.msg_mod_radio_exp.isSelected():
            tab.flip_msg_mod_controls(True)
        self.set_exp_pane_values(tab.msg_mod_exp_pane_scope,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_modify_exp),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_modify_exp_regex) == 'True')
        tab.param_handl_radio_insert.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_insert) == 'True')
        tab.param_handl_radio_replace.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_replace) == 'True')
        tab.param_handl_txtfield_match_indices.setText(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_match_indices))
        self.set_exp_pane_values(tab.param_handl_exp_pane_target,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_match_value),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_match_value_regex) == 'True')
        tab.param_handl_radio_static.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_static) == 'True')
        if tab.param_handl_radio_static.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract, ConfigTab.PARAM_HANDL_RADIO_STATIC_LBL)
        tab.param_handl_radio_extract_cached.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_cached) == 'True')
        if tab.param_handl_radio_extract_cached.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        tab.param_handl_radio_extract_single.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_single) == 'True')
        if tab.param_handl_radio_extract_single.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        tab.param_handl_radio_extract_macro.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_macro) == 'True')
        if tab.param_handl_radio_extract_macro.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        tab.param_handl_txtfield_static_value.setText(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_static_value))
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_cached,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_cached_value),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_cached_regex) == 'True')
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_single,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_single_value),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_single_regex) == 'True')
        tab.https_chkbox.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_https) == 'True')
        tab.update_cookies_chkbox.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_update_cookies) == 'True')
        tab.param_handl_request_editor.setMessage(self._cph.helpers.stringToBytes(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_single_request)), True)
        tab.param_handl_response_editor.setMessage(self._cph.helpers.stringToBytes(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_single_response)), False)
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_macro,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_macro_value),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_macro_regex) == 'True')

    def set_tab_values_from_import(self, tab, tab_name, config):
        self.set_tab_name(tab, tab_name)
        tab_name += '|'
        tab.tabtitle.enable_chkbox.setSelected(
            config[tab_name + self.configname_enabled])
        tab.msg_mod_radio_req.setSelected(
            config[tab_name + self.configname_modify_type_requests])
        tab.msg_mod_radio_resp.setSelected(
            config[tab_name + self.configname_modify_type_responses])
        tab.msg_mod_radio_both.setSelected(
            config[tab_name + self.configname_modify_type_both])
        tab.msg_mod_radio_all.setSelected(
            config[tab_name + self.configname_modify_all])
        if tab.msg_mod_radio_all.isSelected():
            tab.flip_msg_mod_controls(False)
        tab.msg_mod_radio_exp.setSelected(
            config[tab_name + self.configname_modify_match])
        if tab.msg_mod_radio_exp.isSelected():
            tab.flip_msg_mod_controls(True)
        self.set_exp_pane_values(tab.msg_mod_exp_pane_scope,
                                 config[tab_name + self.configname_modify_exp],
                                 config[tab_name + self.configname_modify_exp_regex])
        tab.param_handl_radio_insert.setSelected(
            config[tab_name + self.configname_insert])
        tab.param_handl_radio_replace.setSelected(
            config[tab_name + self.configname_replace])
        tab.param_handl_txtfield_match_indices.setText(
            config[tab_name + self.configname_match_indices])
        self.set_exp_pane_values(tab.param_handl_exp_pane_target,
                                 config[tab_name + self.configname_match_value],
                                 config[tab_name + self.configname_match_value_regex])
        tab.param_handl_radio_static.setSelected(
            config[tab_name + self.configname_static])
        if tab.param_handl_radio_static.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract, ConfigTab.PARAM_HANDL_RADIO_STATIC_LBL)
        tab.param_handl_radio_extract_cached.setSelected(
            config[tab_name + self.configname_cached])
        if tab.param_handl_radio_extract_cached.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        tab.param_handl_radio_extract_single.setSelected(
            config[tab_name + self.configname_single])
        if tab.param_handl_radio_extract_single.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        tab.param_handl_radio_extract_macro.setSelected(
            config[tab_name + self.configname_macro])
        if tab.param_handl_radio_extract_macro.isSelected():
            ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                ConfigTab.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        tab.param_handl_txtfield_static_value.setText(
            config[tab_name + self.configname_static_value])
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_cached,
                                 config[tab_name + self.configname_cached_value],
                                 config[tab_name + self.configname_cached_regex])
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_single,
                                 config[tab_name + self.configname_single_value],
                                 config[tab_name + self.configname_single_regex])
        tab.https_chkbox.setSelected(
            config[tab_name + self.configname_https])
        tab.update_cookies_chkbox.setSelected(
            config[tab_name + self.configname_update_cookies])
        tab.param_handl_request_editor.setMessage(self._cph.helpers.stringToBytes(
            config[tab_name + self.configname_single_request]), True)
        tab.param_handl_response_editor.setMessage(self._cph.helpers.stringToBytes(
            config[tab_name + self.configname_single_response]), False)
        self.set_exp_pane_values(tab.param_handl_exp_pane_extract_macro,
                                 config[tab_name + self.configname_macro_value],
                                 config[tab_name + self.configname_macro_regex])

    def actionPerformed(self, e):
        c = e.getActionCommand()
        if c == self.BTN_QUICKLOAD_LBL or c == self.BTN_IMPORTCONFIG_LBL:
            replace_config_tabs = False
            result = 0
            tabcount = 0
            for tab in self._cph.maintab.get_config_tabs():
                tabcount += 1
            if tabcount > 0:
                result = JOptionPane.showOptionDialog(self,
                                                      'Would you like to Purge or Keep all existing tabs?',
                                                      'Existing Tabs Detected!',
                                                      JOptionPane.YES_NO_CANCEL_OPTION,
                                                      JOptionPane.QUESTION_MESSAGE,
                                                      None,
                                                      ['Purge', 'Keep', 'Cancel'],
                                                      'Cancel')
            if result == 0:  # Replace
                replace_config_tabs = True
                self._cph.issue_log_message('Replacing configuration...', INFO)
            if result != 2 and result != -1:  # Cancel or close dialog
                if result != 0:
                    self._cph.issue_log_message('Merging configuration...', INFO)
                if c == self.BTN_QUICKLOAD_LBL:
                    try:
                        self.tab_names = self._cph.callbacks.loadExtensionSetting(self.configname_tab_names).split(',')
                        self.load_config(replace_config_tabs)
                        self._cph.issue_log_message('Configuration quickloaded.', INFO)
                    except StandardError:
                        self._cph.issue_log_message('Error during quickload.', ERROR, True)
                if c == self.BTN_IMPORTCONFIG_LBL:
                    fc = JFileChooser()
                    result = fc.showOpenDialog(self)
                    if result == JFileChooser.APPROVE_OPTION:
                        fpath = fc.getSelectedFile().getPath()
                        try:
                            with open(fpath, 'rb') as f:
                                self.tab_names = load(f).split(',')
                                config = load(f)
                            self.load_config(replace_config_tabs, config)
                            self._cph.issue_log_message('Configuration imported from "{}".'.format(fpath), INFO)
                        except StandardError:
                            self._cph.issue_log_message('Error importing config from "{}".'.format(fpath), ERROR, True)
                    if result == JFileChooser.CANCEL_OPTION:
                        self._cph.issue_log_message('User canceled configuration import from file.', INFO)
            else:
                self._cph.issue_log_message('User canceled quickload/import.', INFO)

        if c == self.BTN_QUICKSAVE_LBL:
            tabcount = 0
            for tab in self._cph.maintab.get_config_tabs():
                tabcount += 1
                if tabcount > 0:
                    config = self.prepare_to_save()
                    self._cph.callbacks.saveExtensionSetting(self.configname_tab_names, ','.join(self.tab_names))
                    for k, v in config.items():
                        self._cph.callbacks.saveExtensionSetting(k, str(v))

        if c == self.BTN_DOCS_LBL:
            browser_open(self.DOCS_URL)

        if c == self.BTN_EXPORTCONFIG_LBL:
            tabcount = 0
            for tab in self._cph.maintab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                fc = JFileChooser()
                result = fc.showSaveDialog(self)
                if result == JFileChooser.APPROVE_OPTION:
                    fpath = fc.getSelectedFile().getPath()
                    config = self.prepare_to_save()
                    try:
                        with open(fpath, 'wb') as f:
                            dump(','.join(self.tab_names), f)
                            dump(config, f)
                        self._cph.issue_log_message('Configuration exported to "{}".'.format(fpath), INFO)
                    except IOError:
                        self._cph.issue_log_message('Error exporting config to "{}".'.format(fpath), ERROR, True)
                if result == JFileChooser.CANCEL_OPTION:
                    self._cph.issue_log_message('User canceled configuration export to file.', INFO)

    def load_config(self, replace_config_tabs, config=None):
        temp_names = self.tab_names[:]
        tabs_to_remove = {}
        tabcount = len(self.tab_names)

        # Modify existing and mark for purge where applicable
        for tab_name in self.tab_names:
            for tab in self._cph.maintab.get_config_tabs():
                if tab_name == tab.namepane_txtfield.getText():
                    if config is not None:
                        self.set_tab_values_from_import(tab, tab_name, config)
                    else:
                        self.set_tab_values_from_quickload(tab, tab_name)
                    if tab_name in temp_names:
                        temp_names.remove(tab_name)
                    tabs_to_remove[tab] = False
                if tab not in tabs_to_remove:
                    tabs_to_remove[tab] = True
                    tabcount += 1

        # Import and purge if applicable
        for k, v in tabs_to_remove.items():
            if v and replace_config_tabs:
                MainTab.mainpane.remove(k)
        for tab_name in temp_names:
            if config is not None:
                self.set_tab_values_from_import(ConfigTab(self._cph), tab_name, config)
            else:
                self.set_tab_values_from_quickload(ConfigTab(self._cph), tab_name)
            tabcount += 1

        # Match UI to loaded config
        for tab in self._cph.maintab.get_config_tabs():
            if tab.msg_mod_radio_resp.isSelected():
                tab.msg_mod_radio_resp.doClick()
            if tab.msg_mod_radio_both.isSelected():
                tab.msg_mod_radio_both.doClick()

        # Restore tab order
        x = 0
        for tab_name in self.tab_names:
            for tab in self._cph.maintab.get_config_tabs():
                if tab_name == tab.namepane_txtfield.getText():
                    MainTab.mainpane.setSelectedIndex(
                        MainTab.mainpane.indexOfComponent(tab))
                    for i in range(tabcount):
                        ConfigTab.move_tab_back(tab)
                    for i in range(x):
                        ConfigTab.move_tab_fwd(tab)
                    break
            x += 1

        ConfigTab.disable_all_cache_viewers()

    def prepare_to_save(self):
        self.tab_names = []
        config = {}
        i = 1
        for tab in self._cph.maintab.get_config_tabs():
            name = tab.namepane_txtfield.getText()
            if name in self.tab_names:
                name += ' (%s)' % i
                self.set_tab_name(tab, name)
                i += 1
            self.tab_names.append(name)
            name += '|'
            config[name + self.configname_enabled] = tab.tabtitle.enable_chkbox.isSelected()
            config[name + self.configname_modify_type_requests] = tab.msg_mod_radio_req.isSelected()
            config[name + self.configname_modify_type_responses] = tab.msg_mod_radio_resp.isSelected()
            config[name + self.configname_modify_type_both] = tab.msg_mod_radio_both.isSelected()
            config[name + self.configname_modify_all] = tab.msg_mod_radio_all.isSelected()
            config[name + self.configname_modify_match] = tab.msg_mod_radio_exp.isSelected()
            config[name + self.configname_modify_exp], \
            config[name + self.configname_modify_exp_regex] = self.get_exp_pane_values(tab.msg_mod_exp_pane_scope)
            config[name + self.configname_insert] = tab.param_handl_radio_insert.isSelected()
            config[name + self.configname_replace] = tab.param_handl_radio_replace.isSelected()
            config[name + self.configname_match_indices] = tab.param_handl_txtfield_match_indices.getText()
            config[name + self.configname_match_value], \
            config[name + self.configname_match_value_regex] = self.get_exp_pane_values(
                tab.param_handl_exp_pane_target)
            config[name + self.configname_static] = tab.param_handl_radio_static.isSelected()
            config[name + self.configname_cached] = tab.param_handl_radio_extract_cached.isSelected()
            config[name + self.configname_single] = tab.param_handl_radio_extract_single.isSelected()
            config[name + self.configname_macro] = tab.param_handl_radio_extract_macro.isSelected()
            config[name + self.configname_static_value] = tab.param_handl_txtfield_static_value.getText()
            config[name + self.configname_cached_value], \
            config[name + self.configname_cached_regex] = self.get_exp_pane_values(
                tab.param_handl_exp_pane_extract_cached)
            config[name + self.configname_single_value], \
            config[name + self.configname_single_regex] = self.get_exp_pane_values(
                tab.param_handl_exp_pane_extract_single)
            config[name + self.configname_https] = tab.https_chkbox.isSelected()
            config[name + self.configname_update_cookies] = tab.update_cookies_chkbox.isSelected()
            config[name + self.configname_single_request] = self._cph.helpers.bytesToString(
                tab.param_handl_request_editor.getMessage())
            config[name + self.configname_single_response] = self._cph.helpers.bytesToString(
                tab.param_handl_response_editor.getMessage())
            config[name + self.configname_macro_value], \
            config[name + self.configname_macro_regex] = self.get_exp_pane_values(
                tab.param_handl_exp_pane_extract_macro)
        return config


class ConfigTabTitle(JPanel):
    def __init__(self):
        self.setBorder(BorderFactory.createEmptyBorder(-4, -5, -5, -5))
        self.setOpaque(False)
        self.enable_chkbox = JCheckBox('', True)
        self.label = JLabel(ConfigTab.TAB_NEW_NAME)
        self.label.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 4))
        self.add(self.enable_chkbox)
        self.add(self.label)
        self.add(self.CloseButton())

    class CloseButton(JButton, ActionListener):
        def __init__(self):
            self.setText(unichr(0x00d7))  # multiplication sign
            self.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 2))
            SubTab.create_empty_button(self)
            self.addMouseListener(self.CloseButtonMouseListener())
            self.addActionListener(self)

        def actionPerformed(self, e):
            tabindex = MainTab.mainpane.indexOfTabComponent(self.getParent())
            tabcount = MainTab.mainpane.getTabCount()
            if tabcount == 3 or tabindex == tabcount - 2:
                MainTab.mainpane.setSelectedIndex(tabcount - 3)
            MainTab.mainpane.remove(tabindex)
            ConfigTab.disable_all_cache_viewers()

        class CloseButtonMouseListener(MouseAdapter):
            def mouseEntered(self, e):
                button = e.getComponent()
                button.setForeground(Color.red)

            def mouseExited(self, e):
                button = e.getComponent()
                button.setForeground(Color.black)

            def mouseReleased(self, e):
                pass

            def mousePressed(self, e):
                pass


class ConfigTabNameField(JTextField, KeyListener):
    def __init__(self, tab_label):
        self.setColumns(25)
        self.setText(ConfigTab.TAB_NEW_NAME)
        self.addKeyListener(self)
        self.tab_label = tab_label

    def keyReleased(self, e):
        self.tab_label.setText(self.getText())

    def keyPressed(self, e):
        # Doing self._tab_label.setText() here is sub-optimal. Leave it above.
        pass

    def keyTyped(self, e):
        pass


class ConfigTab(SubTab):
    TXT_FIELD_SIZE = 45

    HTTPS_LBL = 'Issue over HTTPS'
    UPDATE_COOKIES_LBL = 'Update cookies'
    MATCH_OPTIONS_LBL = 'Match options'
    REPLACE_OPTIONS_LBL = 'Replace options'
    PARAM_HANDL_BTN_ISSUE_LBL = 'Issue'
    PARAM_HANDL_GROUP_LBL = 'Parameter handling'
    PARAM_HANDL_LBL_EXTRACT_VALUE = 'this request (left) to extract the parameter value from its response (right):'
    PARAM_HANDL_LBL_MATCH_EXP = 'Determine where to insert/replace the parameter using this expression:'
    PARAM_HANDL_LBL_MATCH_RANGE = 'Match indices and/or slices:'
    PARAM_HANDL_LBL_STATIC_VALUE = 'Insert or replace existing value with this one in applicable requests:'
    PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL = 'Extract value from a response after issuing a single request...'
    PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL = 'Extract value from the final response after running a macro...'
    PARAM_HANDL_RADIO_CACHED_EXP_LBL = '... using this Regular Expression:'
    PARAM_HANDL_RADIO_EXTRACT_EXP_LBL = PARAM_HANDL_RADIO_CACHED_EXP_LBL
    PARAM_HANDL_RADIO_INSERT_LBL = 'Insert after match(es)'
    PARAM_HANDL_RADIO_REPLACE_LBL = 'Replace existing match(es)'
    PARAM_HANDL_RADIO_STATIC_LBL = 'Use static value'
    PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL = 'Extract value from the preceding tab\'s cached response...'
    REGEX_LBL = 'RegEx'
    MSG_MOD_GROUP_LBL = 'Message modification/caching scope (always respects suite scope)'
    MSG_MOD_TYPES_TO_MODIFY_LBL = 'Message types to modify:'
    MSG_MOD_RADIO_REQUESTS_LBL = 'Requests'
    MSG_MOD_RADIO_RESPONSES_LBL = 'Responses'
    MSG_MOD_RADIO_BOTH_LBL = 'Requests and Responses'
    MSG_MOD_RADIO_ALL_LBL = 'All {}'
    MSG_MOD_RADIO_EXP_LBL = '{} matching this expression:'
    TAB_NAME_LBL = 'Friendly name:'
    TAB_NEW_NAME = 'Unconfigured'
    BTN_BACK_LBL = '<'
    BTN_FWD_LBL = '>'

    def __init__(self, cph, message=None):
        SubTab.__init__(self, cph)
        self.request, self.response = self.initialize_req_resp()
        self.cached_request, self.cached_response = self.initialize_req_resp()
        if message:
            self.request = message.getRequest()
            resp = message.getResponse()
            if resp:
                self.response = resp
        self.msg_mod_controls_to_toggle = []
        self.cached_match = ''

        index = MainTab.mainpane.getTabCount() - 1
        MainTab.mainpane.add(self, index)
        self.tabtitle = ConfigTabTitle()
        MainTab.mainpane.setTabComponentAt(index, self.tabtitle)
        MainTab.mainpane.setSelectedIndex(index)

        btn_back = JButton(self.BTN_BACK_LBL)
        btn_back.addActionListener(self)
        btn_fwd = JButton(self.BTN_FWD_LBL)
        btn_fwd.addActionListener(self)
        controlpane = JPanel(FlowLayout(FlowLayout.LEADING))
        controlpane.add(btn_back)
        controlpane.add(btn_fwd)

        namepane = JPanel(FlowLayout(FlowLayout.LEADING))
        namepane.add(self.set_title_font(JLabel(self.TAB_NAME_LBL)))
        self.namepane_txtfield = ConfigTabNameField(self.tabtitle.label)
        namepane.add(self.namepane_txtfield)

        self.msg_mod_exp_pane_scope = self.create_expression_pane()
        self.msg_mod_controls_to_toggle = self.msg_mod_exp_pane_scope.getComponents()
        msg_mod_layout_pane = JPanel(GridBagLayout())
        msg_mod_layout_pane.setBorder(BorderFactory.createTitledBorder(self.MSG_MOD_GROUP_LBL))
        msg_mod_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        param_handl_layout_pane = JPanel(GridBagLayout())
        param_handl_layout_pane.setBorder(BorderFactory.createTitledBorder(self.PARAM_HANDL_GROUP_LBL))
        param_handl_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        self.msg_mod_radio_req = JRadioButton(self.MSG_MOD_RADIO_REQUESTS_LBL, True)
        self.msg_mod_radio_req.addActionListener(self)
        self.msg_mod_radio_resp = JRadioButton(self.MSG_MOD_RADIO_RESPONSES_LBL)
        self.msg_mod_radio_resp.addActionListener(self)
        self.msg_mod_radio_both = JRadioButton(self.MSG_MOD_RADIO_BOTH_LBL)
        self.msg_mod_radio_both.addActionListener(self)
        self.msg_mod_radio_all = JRadioButton(self.MSG_MOD_RADIO_ALL_LBL.format(self.MSG_MOD_RADIO_REQUESTS_LBL), True)
        self.msg_mod_radio_all.addActionListener(self)
        self.msg_mod_radio_exp = JRadioButton(self.MSG_MOD_RADIO_EXP_LBL.format(self.MSG_MOD_RADIO_REQUESTS_LBL))
        self.msg_mod_radio_exp.addActionListener(self)
        self.param_handl_radio_insert = JRadioButton(self.PARAM_HANDL_RADIO_INSERT_LBL, True)
        self.param_handl_radio_insert.addActionListener(self)
        self.param_handl_radio_replace = JRadioButton(self.PARAM_HANDL_RADIO_REPLACE_LBL)
        self.param_handl_radio_replace.addActionListener(self)
        self.param_handl_txtfield_match_indices = JTextField()
        self.param_handl_txtfield_match_indices.setText('0')
        self.param_handl_exp_pane_target = self.create_expression_pane()
        self.param_handl_exp_pane_extract_cached = self.create_expression_pane()
        self.param_handl_exp_pane_extract_single = self.create_expression_pane()
        self.param_handl_exp_pane_extract_macro = self.create_expression_pane()
        self.param_handl_txtfield_static_value = JTextField()
        self.param_handl_txtfield_static_value.setColumns(self.TXT_FIELD_SIZE)
        self.param_handl_cached_req_viewer = self._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_cached_req_viewer.setMessage(self.cached_request, False)
        self.param_handl_cached_resp_viewer = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)
        self.param_handl_request_editor = self._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_request_editor.setMessage(self.request, True)
        self.param_handl_response_editor = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_response_editor.setMessage(self.response, False)
        self.param_handl_cardpanel_static_or_extract = JPanel(FlexibleCardLayout())
        self.param_handl_radio_static = JRadioButton(self.PARAM_HANDL_RADIO_STATIC_LBL, True)
        self.param_handl_radio_static.addActionListener(self)
        self.param_handl_radio_extract_cached = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        self.param_handl_radio_extract_cached.addActionListener(self)
        self.param_handl_radio_extract_cached.setEnabled(False)
        self.param_handl_radio_extract_single = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        self.param_handl_radio_extract_single.addActionListener(self)
        self.param_handl_radio_extract_macro = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        self.param_handl_radio_extract_macro.addActionListener(self)
        self.https_chkbox = JCheckBox(self.HTTPS_LBL)
        self.update_cookies_chkbox = JCheckBox(self.UPDATE_COOKIES_LBL, True)

        self.build_msg_mod_pane(msg_mod_layout_pane)
        self.build_param_handl_pane(param_handl_layout_pane)

        if self.request:
            self.param_handl_radio_extract_single.setSelected(True)
            ConfigTab.show_card(self.param_handl_cardpanel_static_or_extract, self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)

        constraints = self.initialize_constraints()
        constraints.anchor = GridBagConstraints.FIRST_LINE_START
        constraints.weighty = 0.05
        self._main_tab_pane.add(controlpane, constraints)
        constraints.gridy = 1
        self._main_tab_pane.add(namepane, constraints)
        constraints.gridy = 2
        self._main_tab_pane.add(msg_mod_layout_pane, constraints)
        constraints.gridy = 3
        constraints.weighty = 1
        self._main_tab_pane.add(param_handl_layout_pane, constraints)

    def initialize_req_resp(self):
        return [], self._cph.helpers.stringToBytes(''.join([' \r\n' for i in range(6)]))

    def create_expression_pane(self):
        pane = JPanel(FlowLayout(FlowLayout.LEADING))
        field = JTextField()
        field.setColumns(self.TXT_FIELD_SIZE)
        box = JCheckBox(self.REGEX_LBL)
        pane.add(field)
        pane.add(box)
        return pane

    def build_msg_mod_pane(self, msg_mod_pane):
        for c in self.msg_mod_controls_to_toggle:
            c.setEnabled(False)

        mod_group = ButtonGroup()
        mod_group.add(self.msg_mod_radio_all)
        mod_group.add(self.msg_mod_radio_exp)

        mod_req_or_resp_group = ButtonGroup()
        mod_req_or_resp_group.add(self.msg_mod_radio_req)
        mod_req_or_resp_group.add(self.msg_mod_radio_resp)
        mod_req_or_resp_group.add(self.msg_mod_radio_both)

        msg_mod_req_or_resp_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        msg_mod_req_or_resp_pane.add(JLabel(self.MSG_MOD_TYPES_TO_MODIFY_LBL))
        msg_mod_req_or_resp_pane.add(self.msg_mod_radio_req)
        msg_mod_req_or_resp_pane.add(self.msg_mod_radio_resp)
        msg_mod_req_or_resp_pane.add(self.msg_mod_radio_both)

        constraints = self.initialize_constraints()
        msg_mod_pane.add(msg_mod_req_or_resp_pane, constraints)
        constraints.gridy = 1
        msg_mod_pane.add(JSeparator(), constraints)
        constraints.gridy = 2
        msg_mod_pane.add(self.create_blank_space(), constraints)
        constraints.gridy = 3
        msg_mod_pane.add(self.msg_mod_radio_all, constraints)
        constraints.gridy = 4
        msg_mod_pane.add(self.msg_mod_radio_exp, constraints)
        constraints.gridy = 5
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        msg_mod_pane.add(self.msg_mod_exp_pane_scope, constraints)

    def build_param_handl_pane(self, param_derivation_pane):
        param_group_1 = ButtonGroup()
        param_group_1.add(self.param_handl_radio_insert)
        param_group_1.add(self.param_handl_radio_replace)

        param_group_2 = ButtonGroup()
        param_group_2.add(self.param_handl_radio_static)
        param_group_2.add(self.param_handl_radio_extract_cached)
        param_group_2.add(self.param_handl_radio_extract_single)
        param_group_2.add(self.param_handl_radio_extract_macro)

        static_param_card = JPanel(GridBagLayout())
        cached_param_card = JPanel(GridBagLayout())
        derive_param_single_card = JPanel(GridBagLayout())
        derive_param_macro_card = JPanel(GridBagLayout())

        constraints = self.initialize_constraints()
        constraints.anchor = GridBagConstraints.FIRST_LINE_START
        static_param_card.add(JLabel(self.PARAM_HANDL_LBL_STATIC_VALUE), constraints)
        constraints.gridy = 1
        static_param_card.add(self.param_handl_txtfield_static_value, constraints)

        constraints = self.initialize_constraints()
        cached_param_card.add(JLabel(self.PARAM_HANDL_RADIO_CACHED_EXP_LBL), constraints)
        constraints.gridy = 1
        cached_param_card.add(self.param_handl_exp_pane_extract_cached, constraints)
        constraints.gridy = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent(self.param_handl_cached_req_viewer.getComponent())
        splitpane.setRightComponent(self.param_handl_cached_resp_viewer.getComponent())
        cached_param_card.add(splitpane, constraints)
        splitpane.setDividerLocation(500)

        # RegEx will always be enabled for these panes.
        regex = self.param_handl_exp_pane_extract_cached.getComponent(1)
        regex.setEnabled(False)
        regex.setSelected(True)
        regex = self.param_handl_exp_pane_extract_single.getComponent(1)
        regex.setEnabled(False)
        regex.setSelected(True)
        regex = self.param_handl_exp_pane_extract_macro.getComponent(1)
        regex.setEnabled(False)
        regex.setSelected(True)

        constraints = self.initialize_constraints()
        derive_param_single_card.add(JLabel(self.PARAM_HANDL_RADIO_EXTRACT_EXP_LBL), constraints)
        constraints.gridy = 1
        derive_param_single_card.add(self.param_handl_exp_pane_extract_single, constraints)
        constraints.gridy = 2
        issue_request_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        issue_request_button = JButton(self.PARAM_HANDL_BTN_ISSUE_LBL)
        issue_request_button.addActionListener(self)
        issue_request_pane.add(issue_request_button)
        issue_request_pane.add(JLabel(self.PARAM_HANDL_LBL_EXTRACT_VALUE))
        derive_param_single_card.add(issue_request_pane, constraints)
        constraints.gridy = 3
        chkbox_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        chkbox_pane.add(self.update_cookies_chkbox)
        chkbox_pane.add(self.https_chkbox)
        derive_param_single_card.add(chkbox_pane, constraints)
        constraints.gridy = 4
        splitpane = JSplitPane()
        splitpane.setLeftComponent(self.param_handl_request_editor.getComponent())
        splitpane.setRightComponent(self.param_handl_response_editor.getComponent())
        derive_param_single_card.add(splitpane, constraints)
        splitpane.setDividerLocation(500)

        constraints = self.initialize_constraints()
        derive_param_macro_card.add(JLabel(self.PARAM_HANDL_RADIO_EXTRACT_EXP_LBL), constraints)
        constraints.gridy = 1
        derive_param_macro_card.add(self.param_handl_exp_pane_extract_macro, constraints)

        self.param_handl_cardpanel_static_or_extract.add(static_param_card, self.PARAM_HANDL_RADIO_STATIC_LBL)
        self.param_handl_cardpanel_static_or_extract.add(cached_param_card, self.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_single_card,
                                                         self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_macro_card,
                                                         self.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)

        constraints = self.initialize_constraints()
        param_derivation_pane.add(self.set_title_font(JLabel(self.MATCH_OPTIONS_LBL)), constraints)
        constraints.gridy = 1
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridy = 2
        param_derivation_pane.add(self.param_handl_radio_insert, constraints)
        constraints.gridx = 1
        param_derivation_pane.add(JLabel(self.PARAM_HANDL_LBL_MATCH_RANGE), constraints)
        constraints.gridy = 3
        constraints.gridx = 0
        param_derivation_pane.add(self.param_handl_radio_replace, constraints)
        constraints.gridx = 1
        param_derivation_pane.add(self.param_handl_txtfield_match_indices, constraints)
        constraints.gridx = 2
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridx = 3
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridx = 0
        constraints.gridy = 4
        param_derivation_pane.add(JLabel(self.PARAM_HANDL_LBL_MATCH_EXP), constraints)
        constraints.gridy = 5
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        param_derivation_pane.add(self.param_handl_exp_pane_target, constraints)
        constraints.gridy = 6
        constraints.gridwidth = GridBagConstraints.REMAINDER
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridy = 7
        param_derivation_pane.add(JSeparator(), constraints)
        constraints.gridy = 8
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridwidth = 1
        constraints.gridy = 9
        param_derivation_pane.add(self.set_title_font(JLabel(self.REPLACE_OPTIONS_LBL)), constraints)
        constraints.gridy = 10
        param_derivation_pane.add(self.create_blank_space(), constraints)
        constraints.gridy = 11
        param_derivation_pane.add(self.param_handl_radio_static, constraints)
        constraints.gridy = 12
        param_derivation_pane.add(self.param_handl_radio_extract_cached, constraints)
        constraints.gridy = 13
        param_derivation_pane.add(self.param_handl_radio_extract_single, constraints)
        constraints.gridy = 14
        param_derivation_pane.add(self.param_handl_radio_extract_macro, constraints)
        constraints.gridy = 15
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        param_derivation_pane.add(self.param_handl_cardpanel_static_or_extract, constraints)

    def flip_msg_mod_controls(self, on_off):
        for control in self.msg_mod_controls_to_toggle:
            control.setEnabled(on_off)

    @staticmethod
    def move_tab_back(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() - 1
        if desired_index > 0:
            MainTab.mainpane.setSelectedIndex(0)
            MainTab.mainpane.add(tab, desired_index)
            MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle)
            MainTab.mainpane.setSelectedIndex(desired_index)

    @staticmethod
    def move_tab_fwd(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1
        if desired_index < MainTab.mainpane.getComponentCount() - 2:
            MainTab.mainpane.setSelectedIndex(0)
            MainTab.mainpane.add(tab, desired_index + 1)
            MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle)
            MainTab.mainpane.setSelectedIndex(desired_index)

    def disable_cache_viewers(self):
        self.cached_request, self.cached_response = self.initialize_req_resp()
        self.param_handl_cached_req_viewer.setMessage(self.cached_request, False)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)
        if self.param_handl_radio_extract_cached.isSelected():
            self.param_handl_radio_static.doClick()
        self.param_handl_radio_extract_cached.setEnabled(False)

    @staticmethod
    def disable_all_cache_viewers():
        for tab in MainTab.mainpane.getComponents():
            if isinstance(tab, ConfigTab):
                tab.disable_cache_viewers()

    def actionPerformed(self, e):
        c = e.getActionCommand()
        if c == self.MSG_MOD_RADIO_REQUESTS_LBL:
            self.msg_mod_radio_all.setText(self.MSG_MOD_RADIO_ALL_LBL.format(self.MSG_MOD_RADIO_REQUESTS_LBL))
            self.msg_mod_radio_exp.setText(self.MSG_MOD_RADIO_EXP_LBL.format(self.MSG_MOD_RADIO_REQUESTS_LBL))
        if c == self.MSG_MOD_RADIO_RESPONSES_LBL:
            self.msg_mod_radio_all.setText(self.MSG_MOD_RADIO_ALL_LBL.format(self.MSG_MOD_RADIO_RESPONSES_LBL))
            self.msg_mod_radio_exp.setText(self.MSG_MOD_RADIO_EXP_LBL.format(self.MSG_MOD_RADIO_RESPONSES_LBL))
        if c == self.MSG_MOD_RADIO_BOTH_LBL:
            self.msg_mod_radio_all.setText(self.MSG_MOD_RADIO_ALL_LBL.format(self.MSG_MOD_RADIO_BOTH_LBL))
            self.msg_mod_radio_exp.setText(self.MSG_MOD_RADIO_EXP_LBL.format(self.MSG_MOD_RADIO_BOTH_LBL))
        if c == self.msg_mod_radio_all.getText():
            self.flip_msg_mod_controls(False)
        if c == self.msg_mod_radio_exp.getText():
            self.flip_msg_mod_controls(True)
        if c == self.PARAM_HANDL_RADIO_STATIC_LBL:
            self.show_card(self.param_handl_cardpanel_static_or_extract, self.PARAM_HANDL_RADIO_STATIC_LBL)
        if c == self.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL:
            self.show_card(self.param_handl_cardpanel_static_or_extract, self.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        if c == self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL:
            self.show_card(self.param_handl_cardpanel_static_or_extract, self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        if c == self.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL:
            self.show_card(self.param_handl_cardpanel_static_or_extract, self.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        if c == self.PARAM_HANDL_BTN_ISSUE_LBL:
            start_new_thread(self._cph.issue_request, (self,))
        if c == self.BTN_BACK_LBL:
            self.move_tab_back(self)
            self.disable_all_cache_viewers()
        if c == self.BTN_FWD_LBL:
            self.move_tab_fwd(self)
            self.disable_all_cache_viewers()


class FlexibleCardLayout(CardLayout):
    def __init__(self):
        super(FlexibleCardLayout, self).__init__()

    def preferredLayoutSize(self, parent):
        current = self.find_current_component(parent)
        if current:
            insets = parent.getInsets()
            pref = current.getPreferredSize()
            pref.width += insets.left + insets.right
            pref.height += insets.top + insets.bottom
            return pref
        return super.preferredLayoutSize(parent)

    @staticmethod
    def find_current_component(parent):
        for comp in parent.getComponents():
            if comp.isVisible():
                return comp
        return None
