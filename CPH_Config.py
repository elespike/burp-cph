########################################################################################################################
#  Begin CPH_Config.py Imports
########################################################################################################################

from logging import (
    DEBUG,
    ERROR,
    INFO,
    WARNING,
    getLevelName,
)
from pickle     import dump, load
from thread     import start_new_thread
from webbrowser import open_new_tab as browser_open

from burp import ITab
from Quickstart import Quickstart

from java.awt import (
    CardLayout,
    Color,
    FlowLayout,
    Font,
    GridBagConstraints,
    GridBagLayout,
    Insets,
)
from java.awt.event import (
    ActionListener,
    KeyListener,
    MouseAdapter,
)
from javax.swing import (
    BorderFactory,
    JButton,
    JCheckBox,
    JComboBox,
    JFileChooser,
    JLabel,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSeparator,
    JSpinner,
    JSplitPane,
    JTabbedPane,
    JTextArea,
    JTextField,
    SpinnerNumberModel,
)
from javax.swing.event import ChangeListener

########################################################################################################################
#  End CPH_Config.py Imports
########################################################################################################################

########################################################################################################################
#  Begin CPH_Config.py
########################################################################################################################

class MainTab(ITab, ChangeListener):
    mainpane = JTabbedPane()
    configtab_names = {}

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

    @staticmethod
    def get_config_tabs():
        components = MainTab.mainpane.getComponents()
        for i in range(len(components)):
            for tab in components:
                if isinstance(tab, ConfigTab) and i == MainTab.mainpane.indexOfComponent(tab):
                    yield tab

    @staticmethod
    def get_config_tab_names():
        for tab in MainTab.get_config_tabs():
            yield tab.namepane_txtfield.getText()

    @staticmethod
    def get_config_tab_cache(tab_name):
        for tab in MainTab.get_config_tabs():
            if tab.namepane_txtfield.getText() == tab_name:
                return tab.cached_request, tab.cached_response

    @staticmethod
    def check_configtab_names():
        x = 0
        for name in MainTab.get_config_tab_names():
            MainTab.configtab_names[x] = name
            x += 1
        indices_to_rename = {}
        for tab_index_1, tab_name_1 in MainTab.configtab_names.items():
            for tab_index_2, tab_name_2 in MainTab.configtab_names.items():
                if tab_name_2 not in indices_to_rename:
                    indices_to_rename[tab_name_2] = []
                if tab_name_1 == tab_name_2 and tab_index_1 != tab_index_2:
                    indices_to_rename[tab_name_2].append(tab_index_2 + 1)
        for k, v in indices_to_rename.items():
            indices_to_rename[k] = set(sorted(v))
        for tab_name, indices in indices_to_rename.items():
            x = 1
            for i in indices:
                OptionsTab.set_tab_name(MainTab.mainpane.getComponentAt(i), tab_name + ' (%s)' % x)
                x += 1

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
        See create_expression_pane() for details
        """
        comp_count = pane.getComponentCount()
        if comp_count == 1:
            # then there's no label and child_pane is the only component
            child_pane = pane.getComponent(0)
        elif comp_count == 2:
            # then there is a label and child_pane is the second component
            child_pane = pane.getComponent(1)
        return child_pane.getComponent(0).getText(), child_pane.getComponent(1).isSelected()

    @staticmethod
    def set_exp_pane_values(pane, text, check):
        """
        See create_expression_pane() for details
        """
        comp_count = pane.getComponentCount()
        if comp_count == 1:
            # then there's no label and child_pane is the only component
            child_pane = pane.getComponent(0)
        elif comp_count == 2:
            # then there is a label and child_pane is the second component
            child_pane = pane.getComponent(1)
        child_pane.getComponent(0).setText(text)
        child_pane.getComponent(1).setSelected(check)

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
    configname_modify_type_choice_index = 'modify_type_choice_index'
    configname_modify_all = 'modify_all'
    configname_modify_match = 'modify_match'
    configname_modify_exp = 'modify_exp'
    configname_modify_exp_regex = 'modify_exp_regex'
    configname_insert = 'insert'
    configname_replace = 'replace'
    configname_indices_first = 'indices_first'
    configname_indices_all = 'indices_all'
    configname_indices_custom = 'indices_custom'
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
            err : ERROR  ,
            warn: WARNING,
            info: INFO   ,
            dbg : DEBUG  ,
        }
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
        quickstart_text_lbl = JLabel(Quickstart.text)
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
            self._cph.logger.setLevel(level)
            self.verbosity_level_lbl.setText(getLevelName(level))

    @staticmethod
    def set_tab_name(tab, tab_name):
        tab.namepane_txtfield.tab_label.setText(tab_name)
        tab.namepane_txtfield.setText(tab_name)

    def set_tab_values_from_quickload(self, tab, tab_name):
        self.set_tab_name(tab, tab_name)
        tab_name += '|'
        tab.tabtitle_pane.enable_chkbox.setSelected(
            self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_enabled) == 'True')
        index = self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_type_choice_index)
        tab.msg_mod_combo_type.setSelectedIndex(
            int(self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_type_choice_index)))
        # tab.msg_mod_radio_all.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_all) == 'True')
        # if tab.msg_mod_radio_all.isSelected():
            # tab.flip_msg_mod_controls(False)
        # tab.msg_mod_radio_exp.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_modify_match) == 'True')
        # if tab.msg_mod_radio_exp.isSelected():
            # tab.flip_msg_mod_controls(True)
        self.set_exp_pane_values(tab.msg_mod_exp_pane_scope,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_modify_exp),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_modify_exp_regex) == 'True')
        # tab.param_handl_radio_insert.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_insert) == 'True')
        # if tab.param_handl_radio_insert.isSelected():
            # tab.param_handl_txtfield_extract_static_label.setText(tab.PARAM_HANDL_LBL_EXTRACT_STATIC.format(tab.PARAM_HANDL_LBL_EXTRACT_STATIC_INSERT))
            # tab.param_handl_exp_pane_target_label.setText(tab.PARAM_HANDL_LBL_MATCH_EXP.format(tab.PARAM_HANDL_LBL_MATCH_EXP_INSERT))
        # tab.param_handl_radio_replace.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_replace) == 'True')
        # if tab.param_handl_radio_replace.isSelected():
            # tab.param_handl_txtfield_extract_static_label.setText(tab.PARAM_HANDL_LBL_EXTRACT_STATIC.format(tab.PARAM_HANDL_LBL_EXTRACT_STATIC_REPLACE))
            # tab.param_handl_exp_pane_target_label.setText(tab.PARAM_HANDL_LBL_MATCH_EXP.format(tab.PARAM_HANDL_LBL_MATCH_EXP_REPLACE))
        # tab.param_handl_radio_indices_first.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_indices_first) == 'True')
        # if tab.param_handl_radio_indices_first.isSelected():
            # tab.param_handl_txtfield_match_indices.setEnabled(False)
        # tab.param_handl_radio_indices_all.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_indices_all) == 'True')
        # if tab.param_handl_radio_indices_all.isSelected():
            # tab.param_handl_txtfield_match_indices.setEnabled(False)
        # tab.param_handl_radio_indices_custom.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_indices_custom) == 'True')
        # if tab.param_handl_radio_indices_custom.isSelected():
            # tab.param_handl_txtfield_match_indices.setEnabled(True)
        # tab.param_handl_txtfield_match_indices.setText(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_match_indices))
        self.set_exp_pane_values(tab.param_handl_exp_pane_target,
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_match_value),
                                 self._cph.callbacks.loadExtensionSetting(
                                     tab_name + self.configname_match_value_regex) == 'True')
        # tab.param_handl_radio_static.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_static) == 'True')
        # if tab.param_handl_radio_static.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract, ConfigTab.PARAM_HANDL_RADIO_STATIC_LBL)
        # tab.param_handl_radio_extract_cached.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_cached) == 'True')
        # if tab.param_handl_radio_extract_cached.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        # tab.param_handl_radio_extract_single.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_single) == 'True')
        # if tab.param_handl_radio_extract_single.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        # tab.param_handl_radio_extract_macro.setSelected(
            # self._cph.callbacks.loadExtensionSetting(tab_name + self.configname_macro) == 'True')
        # if tab.param_handl_radio_extract_macro.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        tab.param_handl_txtfield_extract_static.setText(
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
        tab.tabtitle_pane.enable_chkbox.setSelected(
            config[tab_name + self.configname_enabled])
        tab.msg_mod_combo_type.setSelectedIndex(
            config[tab_name + self.configname_modify_type_choice_index])
        # tab.msg_mod_radio_all.setSelected(
            # config[tab_name + self.configname_modify_all])
        # if tab.msg_mod_radio_all.isSelected():
            # tab.flip_msg_mod_controls(False)
        # tab.msg_mod_radio_exp.setSelected(
            # config[tab_name + self.configname_modify_match])
        # if tab.msg_mod_radio_exp.isSelected():
            # tab.flip_msg_mod_controls(True)
        self.set_exp_pane_values(tab.msg_mod_exp_pane_scope,
                                 config[tab_name + self.configname_modify_exp],
                                 config[tab_name + self.configname_modify_exp_regex])
        # tab.param_handl_radio_insert.setSelected(
            # config[tab_name + self.configname_insert])
        # if tab.param_handl_radio_insert.isSelected():
            # tab.param_handl_txtfield_extract_static_label.setText(tab.PARAM_HANDL_LBL_EXTRACT_STATIC.format(tab.PARAM_HANDL_LBL_EXTRACT_STATIC_INSERT))
            # tab.param_handl_exp_pane_target_label.setText(tab.PARAM_HANDL_LBL_MATCH_EXP.format(tab.PARAM_HANDL_LBL_MATCH_EXP_INSERT))
        # tab.param_handl_radio_replace.setSelected(
            # config[tab_name + self.configname_replace])
        # if tab.param_handl_radio_replace.isSelected():
            # tab.param_handl_txtfield_extract_static_label.setText(tab.PARAM_HANDL_LBL_EXTRACT_STATIC.format(tab.PARAM_HANDL_LBL_EXTRACT_STATIC_REPLACE))
            # tab.param_handl_exp_pane_target_label.setText(tab.PARAM_HANDL_LBL_MATCH_EXP.format(tab.PARAM_HANDL_LBL_MATCH_EXP_REPLACE))
        # tab.param_handl_radio_indices_first.setSelected(
            # config[tab_name + self.configname_indices_first])
        # if tab.param_handl_radio_indices_first.isSelected():
            # tab.param_handl_txtfield_match_indices.setEnabled(False)
        # tab.param_handl_radio_indices_all.setSelected(
            # config[tab_name + self.configname_indices_all])
        # if tab.param_handl_radio_indices_all.isSelected():
            # tab.param_handl_txtfield_match_indices.setEnabled(False)
        # tab.param_handl_radio_indices_custom.setSelected(
            # config[tab_name + self.configname_indices_custom])
        # if tab.param_handl_radio_indices_custom.isSelected():
           # tab.param_handl_txtfield_match_indices.setEnabled(True)
        tab.param_handl_txtfield_match_indices.setText(
            config[tab_name + self.configname_match_indices])
        self.set_exp_pane_values(tab.param_handl_exp_pane_target,
                                 config[tab_name + self.configname_match_value],
                                 config[tab_name + self.configname_match_value_regex])
        # tab.param_handl_radio_static.setSelected(
            # config[tab_name + self.configname_static])
        # if tab.param_handl_radio_static.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract, ConfigTab.PARAM_HANDL_RADIO_STATIC_LBL)
        # tab.param_handl_radio_extract_cached.setSelected(
            # config[tab_name + self.configname_cached])
        # if tab.param_handl_radio_extract_cached.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        # tab.param_handl_radio_extract_single.setSelected(
            # config[tab_name + self.configname_single])
        # if tab.param_handl_radio_extract_single.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        # tab.param_handl_radio_extract_macro.setSelected(
            # config[tab_name + self.configname_macro])
        # if tab.param_handl_radio_extract_macro.isSelected():
            # ConfigTab.show_card(tab.param_handl_cardpanel_static_or_extract,
                                # ConfigTab.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        tab.param_handl_txtfield_extract_static.setText(
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
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
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
                self._cph.logger.info('Replacing configuration...')
            if result != 2 and result != -1:  # Cancel or close dialog
                if result != 0:
                    self._cph.logger.info('Merging configuration...')
                if c == self.BTN_QUICKLOAD_LBL:
                    try:
                        self.tab_names = self._cph.callbacks.loadExtensionSetting(self.configname_tab_names).split(',')
                        self.load_config(replace_config_tabs)
                        self._cph.logger.info('Configuration quickloaded.')
                    except StandardError:
                        self._cph.logger.error('Error during quickload.')
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
                            self._cph.logger.info('Configuration imported from "{}".'.format(fpath))
                        except StandardError:
                            self._cph.logger.exception('Error importing config from "{}".'.format(fpath))
                    if result == JFileChooser.CANCEL_OPTION:
                        self._cph.logger.info('User canceled configuration import from file.')
            else:
                self._cph.logger.info('User canceled quickload/import.')

        if c == self.BTN_QUICKSAVE_LBL:
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                try:
                    config = self.prepare_to_save(MainTab.get_config_tabs)
                    self._cph.callbacks.saveExtensionSetting(self.configname_tab_names, ','.join(self.tab_names))
                    for k, v in config.items():
                        self._cph.callbacks.saveExtensionSetting(k, str(v))
                    self._cph.logger.info('Configuration quicksaved.')
                except StandardError:
                    self._cph.logger.exception('Error during quicksave.')

        if c == self.BTN_DOCS_LBL:
            browser_open(self.DOCS_URL)

        if c == self.BTN_EXPORTCONFIG_LBL:
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                fc = JFileChooser()
                result = fc.showSaveDialog(self)
                if result == JFileChooser.APPROVE_OPTION:
                    fpath = fc.getSelectedFile().getPath()
                    config = self.prepare_to_save(MainTab.get_config_tabs)
                    try:
                        with open(fpath, 'wb') as f:
                            dump(','.join(self.tab_names), f)
                            dump(config, f)
                        self._cph.logger.info('Configuration exported to "{}".'.format(fpath))
                    except IOError:
                        self._cph.logger.exception('Error exporting config to "{}".'.format(fpath))
                if result == JFileChooser.CANCEL_OPTION:
                    self._cph.logger.info('User canceled configuration export to file.')

    def load_config(self, replace_config_tabs, config=None):
        temp_names = self.tab_names[:]
        tabs_to_remove = {}
        tabcount = len(self.tab_names)

        # Modify existing and mark for purge where applicable
        for tab_name in self.tab_names:
            for tab in MainTab.get_config_tabs():
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

        # Restore tab order
        if len(self.tab_names) > 1:
            x = 0
            for tab_name in self.tab_names:
                for tab in MainTab.get_config_tabs():
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

    def prepare_to_save(self, gen_func):
        self.tab_names = []
        config = {}
        tabcount = 0
        _tabs = gen_func.__call__()
        for tab in _tabs:
            tabcount += 1
            if tabcount > 1:
                MainTab.check_configtab_names()

        # Need to reset the iterator!
        _tabs = gen_func.__call__()
        for tab in _tabs:
            name = tab.namepane_txtfield.getText()
            self.tab_names.append(name)
            name += '|'
            config[name + self.configname_enabled] = tab.tabtitle_pane.enable_chkbox.isSelected()
            config[name + self.configname_modify_type_choice_index] = tab.msg_mod_combo_type.getSelectedIndex()
            # config[name + self.configname_modify_all] = tab.msg_mod_radio_all.isSelected()
            # config[name + self.configname_modify_match] = tab.msg_mod_radio_exp.isSelected()
            config[name + self.configname_modify_exp], \
            config[name + self.configname_modify_exp_regex] = self.get_exp_pane_values(tab.msg_mod_exp_pane_scope)
            # config[name + self.configname_insert] = tab.param_handl_radio_insert.isSelected()
            # config[name + self.configname_replace] = tab.param_handl_radio_replace.isSelected()
            # config[name + self.configname_indices_first] = tab.param_handl_radio_indices_first.isSelected()
            # config[name + self.configname_indices_all] = tab.param_handl_radio_indices_all.isSelected()
            # config[name + self.configname_indices_custom] = tab.param_handl_radio_indices_custom.isSelected()
            config[name + self.configname_match_indices] = tab.param_handl_txtfield_match_indices.getText()
            config[name + self.configname_match_value], \
            config[name + self.configname_match_value_regex] = self.get_exp_pane_values(
                tab.param_handl_exp_pane_target)
            # config[name + self.configname_static] = tab.param_handl_radio_static.isSelected()
            # config[name + self.configname_cached] = tab.param_handl_radio_extract_cached.isSelected()
            # config[name + self.configname_single] = tab.param_handl_radio_extract_single.isSelected()
            # config[name + self.configname_macro] = tab.param_handl_radio_extract_macro.isSelected()
            config[name + self.configname_static_value] = tab.param_handl_txtfield_extract_static.getText()
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

    # TODO organize this
    HTTPS_LBL = 'Issue over HTTPS'
    UPDATE_COOKIES_LBL = 'Update cookies'
    INSERT_REPLACE_LBL = '{}the following:'
    PARAM_HANDL_BTN_ISSUE_LBL = 'Issue'
    PARAM_HANDL_GROUP_LBL = 'Parameter handling'
    PARAM_HANDL_LBL_EXTRACT_SINGLE = 'the request in the left pane, then extract the value from its response with this expression:'
    PARAM_HANDL_LBL_EXTRACT_MACRO = 'When invoked from a Session Handling Rule, CPH will extract the value from the final macro response with this expression:'
    PARAM_HANDL_LBL_EXTRACT_CACHED_PRE = 'Extract the value from'
    PARAM_HANDL_LBL_EXTRACT_CACHED_POST = '\'s cached response with this expression:'
    PARAM_HANDL_LBL_MATCH_EXP = 'Find this expression -'
    PARAM_HANDL_LBL_ACTION = 'then,'
    PARAM_HANDL_LBL_MATCH_RANGE = 'of the matches'
    PARAM_HANDL_LBL_MATCH_SUBSET = '- which subset?'
    PARAM_HANDL_COMBO_INDICES_FIRST  = 'the first'
    PARAM_HANDL_COMBO_INDICES_EACH   = 'each'
    PARAM_HANDL_COMBO_INDICES_SUBSET = 'a subset'
    PARAM_HANDL_COMBO_INDICES_CHOICES = [
        PARAM_HANDL_COMBO_INDICES_FIRST ,
        PARAM_HANDL_COMBO_INDICES_EACH  ,
        PARAM_HANDL_COMBO_INDICES_SUBSET,
    ]
    PARAM_HANDL_COMBO_EXTRACT_STATIC = 'a static value specified below'
    PARAM_HANDL_COMBO_EXTRACT_SINGLE = 'a value returned by issuing a single request'
    PARAM_HANDL_COMBO_EXTRACT_MACRO  = 'a value returned by issuing a sequence of requests'
    PARAM_HANDL_COMBO_EXTRACT_CACHED = 'a value in the cached response of a previous CPH tab'
    PARAM_HANDL_COMBO_EXTRACT_CHOICES = [
        PARAM_HANDL_COMBO_EXTRACT_STATIC,
        PARAM_HANDL_COMBO_EXTRACT_SINGLE,
        PARAM_HANDL_COMBO_EXTRACT_MACRO ,
        PARAM_HANDL_COMBO_EXTRACT_CACHED,
    ]
    PARAM_HANDL_LBL_EXTRACT_STATIC = 'Please note: line separators in this multiline field will be converted to 0x0d0a in the resulting HTTP request'
    PARAM_HANDL_COMBO_ACTION_INSERT = 'insert after'
    PARAM_HANDL_COMBO_ACTION_REPLACE = 'replace'
    PARAM_HANDL_COMBO_ACTION_CHOICES = [PARAM_HANDL_COMBO_ACTION_INSERT, PARAM_HANDL_COMBO_ACTION_REPLACE]
    PARAM_HANDL_RADIO_STATIC_LBL = 'Use static value'
    REGEX_LBL = 'RegEx'

    MSG_MOD_GROUP_LBL = 'Scoping'
    MSG_MOD_TYPES_TO_MODIFY_LBL = 'this tab will work'
    MSG_MOD_COMBO_TYPE_REQ  = 'requests'
    MSG_MOD_COMBO_TYPE_RESP = 'responses'
    MSG_MOD_COMBO_TYPE_BOTH = 'requests and responses'
    MSG_MOD_COMBO_TYPE_CHOICES = [
        MSG_MOD_COMBO_TYPE_REQ,
        MSG_MOD_COMBO_TYPE_RESP,
        MSG_MOD_COMBO_TYPE_BOTH,
    ]
    MSG_MOD_COMBO_SCOPE_ALL = 'on all'
    MSG_MOD_COMBO_SCOPE_SOME = 'only on'
    MSG_MOD_COMBO_SCOPE_CHOICES = [
        MSG_MOD_COMBO_SCOPE_ALL,
        MSG_MOD_COMBO_SCOPE_SOME,
    ]
    MSG_MOD_LBL_SCOPE_SOME = ' containing this expression:'
    MSG_MOD_LBL_SCOPE_BURP = 'Provided their URLs are within Burp Suite\'s scope,'

    TAB_NAME_LBL = 'Friendly name:'
    TAB_NEW_NAME = 'Unconfigured'
    BTN_BACK_LBL = '<'
    BTN_FWD_LBL = '>'
    BTN_CLONETAB_LBL = 'Clone'

    def __init__(self, cph, message=None):
        SubTab.__init__(self, cph)
        self.request, self.response = self.initialize_req_resp()
        self.cached_request, self.cached_response = self.initialize_req_resp()
        if message:
            self.request = message.getRequest()
            resp = message.getResponse()
            if resp:
                self.response = resp
        # self.msg_mod_controls_to_toggle = []
        self.cached_match = ''

        index = MainTab.mainpane.getTabCount() - 1
        MainTab.mainpane.add(self, index)
        self.tabtitle_pane = ConfigTabTitle()
        MainTab.mainpane.setTabComponentAt(index, self.tabtitle_pane)
        MainTab.mainpane.setSelectedIndex(index)

        btn_back = JButton(self.BTN_BACK_LBL)
        btn_back.addActionListener(self)
        btn_fwd = JButton(self.BTN_FWD_LBL)
        btn_fwd.addActionListener(self)
        btn_clonetab = JButton(self.BTN_CLONETAB_LBL)
        btn_clonetab.addActionListener(self)
        controlpane = JPanel(FlowLayout(FlowLayout.LEADING))
        controlpane.add(btn_back)
        controlpane.add(btn_fwd)
        controlpane.add(self.create_blank_space())
        controlpane.add(btn_clonetab)

        namepane = JPanel(FlowLayout(FlowLayout.LEADING))
        namepane.add(self.set_title_font(JLabel(self.TAB_NAME_LBL)))
        self.namepane_txtfield = ConfigTabNameField(self.tabtitle_pane.label)
        namepane.add(self.namepane_txtfield)

        # TODO organize this
        self.msg_mod_exp_pane_scope_lbl = JLabel(self.MSG_MOD_LBL_SCOPE_SOME)
        self.msg_mod_exp_pane_scope_lbl.setVisible(False)
        self.msg_mod_exp_pane_scope = self.create_expression_pane()
        self.msg_mod_exp_pane_scope.setVisible(False)
        # self.msg_mod_controls_to_toggle = self.msg_mod_exp_pane_scope.getComponents()
        msg_mod_layout_pane = JPanel(GridBagLayout())
        msg_mod_layout_pane.setBorder(BorderFactory.createTitledBorder(self.MSG_MOD_GROUP_LBL))
        msg_mod_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        param_handl_layout_pane = JPanel(GridBagLayout())
        param_handl_layout_pane.setBorder(BorderFactory.createTitledBorder(self.PARAM_HANDL_GROUP_LBL))
        param_handl_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        self.msg_mod_combo_scope = JComboBox(self.MSG_MOD_COMBO_SCOPE_CHOICES)
        self.msg_mod_combo_scope.addActionListener(self)
        self.msg_mod_combo_type = JComboBox(self.MSG_MOD_COMBO_TYPE_CHOICES)
        self.msg_mod_combo_type.addActionListener(self)
        # self.msg_mod_radio_all = JRadioButton(self.MSG_MOD_RADIO_ALL_LBL.format(self.msg_mod_combo.getSelectedItem()), True)
        # self.msg_mod_radio_all.addActionListener(self)
        # self.msg_mod_radio_exp = JRadioButton(self.MSG_MOD_RADIO_EXP_LBL.format(self.msg_mod_combo.getSelectedItem()))
        # self.msg_mod_radio_exp.addActionListener(self)
        self.param_handl_combo_action = JComboBox(self.PARAM_HANDL_COMBO_ACTION_CHOICES)
        self.param_handl_combo_action.addActionListener(self)
        # self.param_handl_radio_insert = JRadioButton(self.PARAM_HANDL_RADIO_INSERT_LBL, True)
        # self.param_handl_radio_insert.addActionListener(self)
        # self.param_handl_radio_replace = JRadioButton(self.PARAM_HANDL_RADIO_REPLACE_LBL)
        # self.param_handl_radio_replace.addActionListener(self)
        self.param_handl_combo_indices = JComboBox(self.PARAM_HANDL_COMBO_INDICES_CHOICES)
        self.param_handl_combo_indices.addActionListener(self)
        # self.param_handl_radio_indices_first = JRadioButton(self.PARAM_HANDL_RADIO_INDICES_FIRST_LBL, True)
        # self.param_handl_radio_indices_first.addActionListener(self)
        # self.param_handl_radio_indices_all = JRadioButton(self.PARAM_HANDL_RADIO_INDICES_ALL_LBL)
        # self.param_handl_radio_indices_all.addActionListener(self)
        # self.param_handl_radio_indices_custom = JRadioButton(self.PARAM_HANDL_RADIO_INDICES_CUSTOM_LBL)
        # self.param_handl_radio_indices_custom.addActionListener(self)
        self.param_handl_txtfield_match_indices = JTextField(12)
        self.param_handl_txtfield_match_indices.setText('0')
        self.param_handl_txtfield_match_indices.setEnabled(False)
        self.param_handl_exp_pane_target = self.create_expression_pane()
        self.param_handl_insert_replace_lbl = self.set_title_font(JLabel(self.INSERT_REPLACE_LBL.format('')))
        self.param_handl_subset_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        self.param_handl_exp_pane_extract_cached = self.create_expression_pane(enforce_regex=True)
        self.param_handl_exp_pane_extract_single = self.create_expression_pane(enforce_regex=True)
        self.param_handl_exp_pane_extract_macro = self.create_expression_pane(enforce_regex=True, label=self.PARAM_HANDL_LBL_EXTRACT_MACRO)
        # self.param_handl_txtfield_extract_static_label = JLabel(self.PARAM_HANDL_LBL_EXTRACT_STATIC)
        self.param_handl_txtfield_extract_static = JTextArea()
        self.param_handl_txtfield_extract_static.setColumns(self.TXT_FIELD_SIZE)
        self.param_handl_cached_req_viewer = self._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_cached_req_viewer.setMessage(self.cached_request, False) # False here to make it read-only
        self.param_handl_cached_resp_viewer = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)
        self.param_handl_request_editor = self._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_request_editor.setMessage(self.request, True)
        self.param_handl_response_editor = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_response_editor.setMessage(self.response, False)
        self.param_handl_cardpanel_static_or_extract = JPanel(FlexibleCardLayout())
        self.param_handl_combo_extract = JComboBox(self.PARAM_HANDL_COMBO_EXTRACT_CHOICES)
        self.param_handl_combo_extract.addActionListener(self)
        self.param_handl_combo_cached = JComboBox()
        self.param_handl_combo_cached.addActionListener(self)
        # self.param_handl_radio_static = JRadioButton(self.PARAM_HANDL_RADIO_STATIC_LBL, True)
        # self.param_handl_radio_static.addActionListener(self)
        # self.param_handl_radio_extract_cached = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_CACHED_LBL)
        # self.param_handl_radio_extract_cached.addActionListener(self)
        # self.param_handl_radio_extract_cached.setEnabled(False)
        # self.param_handl_radio_extract_single = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_SINGLE_LBL)
        # self.param_handl_radio_extract_single.addActionListener(self)
        # self.param_handl_radio_extract_macro = JRadioButton(self.PARAM_HANDL_RADIO_EXTRACT_MACRO_LBL)
        # self.param_handl_radio_extract_macro.addActionListener(self)
        self.https_chkbox = JCheckBox(self.HTTPS_LBL)
        self.update_cookies_chkbox = JCheckBox(self.UPDATE_COOKIES_LBL, True)

        self.build_msg_mod_pane(msg_mod_layout_pane)
        self.build_param_handl_pane(param_handl_layout_pane)

        if self.request:
            # TODO fix this after UI changes
            self.param_handl_combo_extract.setSelectedItem(self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)

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

    def create_expression_pane(self, enforce_regex=False, label=None):
        field = JTextField()
        field.setColumns(self.TXT_FIELD_SIZE)

        box = JCheckBox(self.REGEX_LBL)
        if enforce_regex:
            box.setEnabled(False)
            box.setSelected(True)

        child_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        child_pane.add(field)
        child_pane.add(box)

        parent_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        if label:
            parent_pane.add(JLabel(label), constraints)
            constraints.gridy += 1
        parent_pane.add(child_pane, constraints)

        return parent_pane

    def build_msg_mod_pane(self, msg_mod_pane):
        # for c in self.msg_mod_controls_to_toggle:
            # c.setEnabled(False)

        msg_mod_req_or_resp_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        msg_mod_req_or_resp_pane.add(JLabel(self.MSG_MOD_TYPES_TO_MODIFY_LBL))
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_scope)
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_type)
        msg_mod_req_or_resp_pane.add(self.msg_mod_exp_pane_scope_lbl)

        constraints = self.initialize_constraints()
        msg_mod_pane.add(self.set_title_font(JLabel(self.MSG_MOD_LBL_SCOPE_BURP)), constraints)
        constraints.gridy = 1
        msg_mod_pane.add(msg_mod_req_or_resp_pane, constraints)
        constraints.gridy = 2
        msg_mod_pane.add(self.msg_mod_exp_pane_scope, constraints)

    def build_param_handl_pane(self, param_derivation_pane):
        action_indices_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        action_indices_pane.add(self.param_handl_combo_action)
        action_indices_pane.add(self.param_handl_combo_indices)
        action_indices_pane.add(self.set_title_font(JLabel(self.PARAM_HANDL_LBL_MATCH_RANGE)))

        self.param_handl_subset_pane.add(JLabel(self.PARAM_HANDL_LBL_MATCH_SUBSET))
        self.param_handl_subset_pane.add(self.param_handl_txtfield_match_indices)
        self.param_handl_subset_pane.setVisible(False)

        static_param_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        static_param_card.add(self.param_handl_txtfield_extract_static, constraints)
        constraints.gridy = 1
        static_param_card.add(JLabel(self.PARAM_HANDL_LBL_EXTRACT_STATIC), constraints)

        derive_param_single_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        chkbox_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        chkbox_pane.add(self.update_cookies_chkbox)
        chkbox_pane.add(self.https_chkbox)
        derive_param_single_card.add(chkbox_pane, constraints)
        constraints.gridy = 1
        issue_request_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        # TODO any way to validate that the text in there is a valid HTTP request and disable the button otherwise?
        issue_request_button = JButton(self.PARAM_HANDL_BTN_ISSUE_LBL)
        issue_request_button.addActionListener(self)
        issue_request_pane.add(issue_request_button)
        issue_request_pane.add(JLabel(self.PARAM_HANDL_LBL_EXTRACT_SINGLE))
        derive_param_single_card.add(issue_request_pane, constraints)
        constraints.gridy = 2
        derive_param_single_card.add(self.param_handl_exp_pane_extract_single, constraints)
        constraints.gridy = 3
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent(self.param_handl_request_editor.getComponent())
        splitpane.setRightComponent(self.param_handl_response_editor.getComponent())
        derive_param_single_card.add(splitpane, constraints)
        splitpane.setDividerLocation(500)

        derive_param_macro_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        derive_param_macro_card.add(self.param_handl_exp_pane_extract_macro, constraints)

        cached_param_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        tab_choice_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_LBL_EXTRACT_CACHED_PRE))
        tab_choice_pane.add(self.param_handl_combo_cached)
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_LBL_EXTRACT_CACHED_POST))
        cached_param_card.add(tab_choice_pane, constraints)
        constraints.gridy = 1
        cached_param_card.add(self.param_handl_exp_pane_extract_cached, constraints)
        constraints.gridy = 2
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent(self.param_handl_cached_req_viewer.getComponent())
        splitpane.setRightComponent(self.param_handl_cached_resp_viewer.getComponent())
        cached_param_card.add(splitpane, constraints)
        splitpane.setDividerLocation(500)

        self.param_handl_cardpanel_static_or_extract.add(static_param_card, self.PARAM_HANDL_COMBO_EXTRACT_STATIC)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_single_card, self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_macro_card, self.PARAM_HANDL_COMBO_EXTRACT_MACRO)
        self.param_handl_cardpanel_static_or_extract.add(cached_param_card, self.PARAM_HANDL_COMBO_EXTRACT_CACHED)

        constraints = self.initialize_constraints()
        param_derivation_pane.add(self.set_title_font(JLabel(self.PARAM_HANDL_LBL_MATCH_EXP)), constraints)
        constraints.gridy = 1
        param_derivation_pane.add(self.param_handl_exp_pane_target, constraints)
        constraints.gridy = 2
        param_derivation_pane.add(self.set_title_font(JLabel(self.PARAM_HANDL_LBL_ACTION)), constraints)
        constraints.gridy = 3
        param_derivation_pane.add(action_indices_pane, constraints)
        constraints.gridy = 4
        param_derivation_pane.add(self.param_handl_subset_pane, constraints)
        constraints.gridy = 5
        param_derivation_pane.add(self.param_handl_insert_replace_lbl, constraints)
        constraints.gridy = 6
        # Making a FlowLayout panel here so the combo box doesn't stretch
        combo_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        combo_pane.add(self.param_handl_combo_extract)
        combo_pane.add(self.create_blank_space())
        param_derivation_pane.add(combo_pane, constraints)
        constraints.gridy = 7
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        param_derivation_pane.add(self.param_handl_cardpanel_static_or_extract, constraints)

    # def flip_msg_mod_controls(self, on_off):
        # for control in self.msg_mod_controls_to_toggle:
            # control.setEnabled(on_off)

    @staticmethod
    def move_tab_back(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() - 1
        if desired_index > 0:
            MainTab.mainpane.setSelectedIndex(0)
            MainTab.mainpane.add(tab, desired_index)
            MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle_pane)
            MainTab.mainpane.setSelectedIndex(desired_index)

    @staticmethod
    def move_tab_fwd(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1
        if desired_index < MainTab.mainpane.getComponentCount() - 2:
            MainTab.mainpane.setSelectedIndex(0)
            MainTab.mainpane.add(tab, desired_index + 1)
            MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle_pane)
            MainTab.mainpane.setSelectedIndex(desired_index)

    def clone_tab(self, tab):
        def gen_func():
            for _tab in [tab]:
                yield _tab
        desired_index = MainTab.mainpane.getSelectedIndex() + 1
        newtab = ConfigTab(self._cph)
        OptionsTab.set_tab_name(newtab, tab.namepane_txtfield.getText())
        config = self._cph.maintab.options_tab.prepare_to_save(gen_func)
        self._cph.maintab.options_tab.load_config(False, config)
        if desired_index < MainTab.mainpane.getComponentCount() - 2:
            MainTab.mainpane.setSelectedIndex(0)
            MainTab.mainpane.add(newtab, desired_index)
            MainTab.mainpane.setTabComponentAt(desired_index, newtab.tabtitle_pane)
            MainTab.mainpane.setSelectedIndex(desired_index)
        self._cph.maintab.options_tab.prepare_to_save(MainTab.get_config_tabs)

    def disable_cache_viewers(self):
        self.cached_request, self.cached_response = self.initialize_req_resp()
        self.param_handl_cached_req_viewer.setMessage(self.cached_request, False)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)

    @staticmethod
    def disable_all_cache_viewers():
        for tab in MainTab.mainpane.getComponents():
            if isinstance(tab, ConfigTab):
                tab.disable_cache_viewers()

    def actionPerformed(self, e):
        c = e.getActionCommand()
        if c == 'comboBoxChanged':
            c = e.getSource().getSelectedItem()

        if c in self.MSG_MOD_COMBO_SCOPE_CHOICES:
            if c == self.MSG_MOD_COMBO_SCOPE_ALL:
                self.msg_mod_exp_pane_scope_lbl.setVisible(False)
                self.msg_mod_exp_pane_scope.setVisible(False)
            if c == self.MSG_MOD_COMBO_SCOPE_SOME:
                self.msg_mod_exp_pane_scope_lbl.setVisible(True)
                self.msg_mod_exp_pane_scope.setVisible(True)

        if c in self.PARAM_HANDL_COMBO_ACTION_CHOICES:
            if c == self.PARAM_HANDL_COMBO_ACTION_INSERT:
                self.param_handl_insert_replace_lbl.setText(self.INSERT_REPLACE_LBL.format(''))
            if c == self.PARAM_HANDL_COMBO_ACTION_REPLACE:
                self.param_handl_insert_replace_lbl.setText(self.INSERT_REPLACE_LBL.format('with '))

        if c in self.PARAM_HANDL_COMBO_INDICES_CHOICES:
            if c == self.PARAM_HANDL_COMBO_INDICES_FIRST:
                self.param_handl_txtfield_match_indices.setEnabled(False)
                self.param_handl_txtfield_match_indices.setText('0')
                self.param_handl_subset_pane.setVisible(False)
            if c == self.PARAM_HANDL_COMBO_INDICES_EACH:
                self.param_handl_txtfield_match_indices.setEnabled(False)
                self.param_handl_txtfield_match_indices.setText('0:-1,-1')
                self.param_handl_subset_pane.setVisible(False)
            if c == self.PARAM_HANDL_COMBO_INDICES_SUBSET:
                self.param_handl_txtfield_match_indices.setEnabled(True)
                self.param_handl_subset_pane.setVisible(True)

        if c in self.PARAM_HANDL_COMBO_EXTRACT_CHOICES:
            self.show_card(self.param_handl_cardpanel_static_or_extract, c)

        # Set the cached request/response viewers to the selected tab's cache
        if c in MainTab.get_config_tab_names():
            req, resp = MainTab.get_config_tab_cache(c)
            if req and resp:
                self.param_handl_cached_req_viewer.setMessage(req, True)
                self.param_handl_cached_resp_viewer.setMessage(resp, False)

        if c == self.PARAM_HANDL_BTN_ISSUE_LBL:
            start_new_thread(self._cph.issue_request, (self,))

        if c == self.BTN_BACK_LBL:
            self.move_tab_back(self)
            self.disable_all_cache_viewers()
        if c == self.BTN_FWD_LBL:
            self.move_tab_fwd(self)
            self.disable_all_cache_viewers()

        if c == self.BTN_CLONETAB_LBL:
            self.clone_tab(self)
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

########################################################################################################################
#  End CPH_Config.py
########################################################################################################################
