########################################################################################################################
#  Begin CPH_Config.py Imports
########################################################################################################################

from logging import (
    DEBUG       ,
    ERROR       ,
    INFO        ,
    WARNING     ,
    getLevelName,
)
from collections import OrderedDict as odict, namedtuple
from difflib     import unified_diff
from itertools   import product
from json        import dump, dumps, load, loads
from re          import escape as re_escape
from thread      import start_new_thread
from webbrowser  import open_new_tab as browser_open

from burp import ITab
from CPH_Help import CPH_Help

from java.awt import (
    CardLayout        ,
    Color             ,
    FlowLayout        ,
    Font              ,
    GridBagConstraints,
    GridBagLayout     ,
    Insets            ,
)
from java.awt.event import (
    ActionListener,
    KeyListener   ,
    MouseAdapter  ,
)
from javax.swing import (
    AbstractAction    ,
    BorderFactory     ,
    JButton           ,
    JCheckBox         ,
    JComboBox         ,
    JFileChooser      ,
    JFrame            ,
    JLabel            ,
    JOptionPane       ,
    JPanel            ,
    JScrollPane       ,
    JSeparator        ,
    JSpinner          ,
    JSplitPane        ,
    JTabbedPane       ,
    JTable            ,
    JTextArea         ,
    JTextField        ,
    KeyStroke         ,
    SpinnerNumberModel,
)
from javax.swing.event       import ChangeListener, ListSelectionListener
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table       import AbstractTableModel
from javax.swing.undo        import UndoManager

########################################################################################################################
#  End CPH_Config.py Imports
########################################################################################################################

########################################################################################################################
#  Begin CPH_Config.py
########################################################################################################################

class MainTab(ITab, ChangeListener):
    mainpane = JTabbedPane()

    # This is set during __init__
    logger = None

    def __init__(self, cph):
        MainTab.mainpane.addChangeListener(self)
        self._cph = cph
        MainTab.logger = cph.logger
        self.options_tab = OptionsTab(cph)
        MainTab.mainpane.add('Options', self.options_tab)
        self._add_sign = unichr(0x002b)  # addition sign
        MainTab.mainpane.add(self._add_sign, JPanel())

        class Action(AbstractAction):
            def __init__(self, action):
                self.action = action
            def actionPerformed(self, e):
                if self.action:
                    self.action()

        # Ctrl+N only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(78, 2, True), 'add_config_tab')
        MainTab.mainpane.getActionMap().put('add_config_tab', Action(lambda: ConfigTab(self._cph)))

        # Ctrl+Shift+N only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(78, 3, True), 'clone_tab')
        MainTab.mainpane.getActionMap().put(
            'clone_tab',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().clone_tab()
                if MainTab.mainpane.getSelectedIndex() > 0
                else None
            )
        )

        # Ctrl+W only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(87, 2, True), 'close_tab')
        MainTab.mainpane.getActionMap().put('close_tab', Action(MainTab.close_tab))

        # Ctrl+E only on key released
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(69, 2, True), 'toggle_tab')
        MainTab.mainpane.getActionMap().put(
            'toggle_tab',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().tabtitle_pane.enable_chkbox.setSelected(
                    not MainTab.mainpane.getSelectedComponent().tabtitle_pane.enable_chkbox.isSelected()
                )
            )
        )

        # Ctrl+,
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(44, 2), 'select_previous_tab')
        MainTab.mainpane.getActionMap().put(
            'select_previous_tab',
            Action(
                lambda: MainTab.mainpane.setSelectedIndex(MainTab.mainpane.getSelectedIndex() - 1)
                if MainTab.mainpane.getSelectedIndex() > 0
                else MainTab.mainpane.setSelectedIndex(0)
            )
        )

        # Ctrl+.
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(46, 2), 'select_next_tab')
        MainTab.mainpane.getActionMap().put(
            'select_next_tab',
            Action(lambda: MainTab.mainpane.setSelectedIndex(MainTab.mainpane.getSelectedIndex() + 1))
        )

        # Ctrl+Shift+,
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(44, 3), 'move_tab_back')
        MainTab.mainpane.getActionMap().put(
            'move_tab_back',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().move_tab_back(
                    MainTab.mainpane.getSelectedComponent()
                )
            )
        )

        # Ctrl+Shift+.
        MainTab.mainpane.getInputMap(1).put(KeyStroke.getKeyStroke(46, 3), 'move_tab_fwd')
        MainTab.mainpane.getActionMap().put(
            'move_tab_fwd',
            Action(
                lambda: MainTab.mainpane.getSelectedComponent().move_tab_fwd(
                    MainTab.mainpane.getSelectedComponent()
                )
            )
        )

    @staticmethod
    def getTabCaption():
        return 'CPH Config'

    @staticmethod
    def getOptionsTab():
        return MainTab.mainpane.getComponentAt(0)

    def getUiComponent(self):
        return MainTab.mainpane

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
        configtab_names = {}
        for name in MainTab.get_config_tab_names():
            configtab_names[x] = name
            x += 1
        indices_to_rename = {}
        for tab_index_1, tab_name_1 in configtab_names.items():
            for tab_index_2, tab_name_2 in configtab_names.items():
                if tab_name_2 not in indices_to_rename:
                    indices_to_rename[tab_name_2] = []
                if tab_name_1 == tab_name_2 and tab_index_1 != tab_index_2:
                    indices_to_rename[tab_name_2].append(tab_index_2 + 1) # +1 because the first tab is the Options tab
        for k, v in indices_to_rename.items():
            indices_to_rename[k] = set(sorted(v))
        for tab_name, indices in indices_to_rename.items():
            x = 1
            for i in indices:
                MainTab.set_tab_name(MainTab.mainpane.getComponentAt(i), tab_name + ' (%s)' % x)
                x += 1

    @staticmethod
    def set_tab_name(tab, tab_name):
        tab.namepane_txtfield.tab_label.setText(tab_name)
        tab.namepane_txtfield.setText(tab_name)
        emv_tab_index = MainTab.mainpane.indexOfComponent(tab) - 1
        MainTab.getOptionsTab().emv_tab_pane.setTitleAt(emv_tab_index, tab_name)

    @staticmethod
    def close_tab(tab_index=None):
        if tab_index is None:
            tab_index = MainTab.mainpane.getSelectedIndex()
        true_index = tab_index - 1 # because of the Options tab
        tab_count = MainTab.mainpane.getTabCount()
        if tab_index == 0 or tab_count == 2:
            return
        if tab_count == 3 or tab_index == tab_count - 2:
            MainTab.mainpane.setSelectedIndex(tab_count - 3)
        MainTab.mainpane.remove(tab_index)
        MainTab.getOptionsTab().emv_tab_pane.remove(true_index)

        # If the closed tab was selected in subsequent tabs' combo_cached, remove selection.
        for i, subsequent_tab in enumerate(MainTab.get_config_tabs()):
            if i < true_index:
                continue
            if subsequent_tab.param_handl_combo_cached.getSelectedIndex() == true_index:
                subsequent_tab.param_handl_combo_cached.setSelectedItem(None)
                if subsequent_tab.param_handl_combo_extract.getSelectedItem() == ConfigTab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                    MainTab.logger.warning(
                        'Selected cache no longer available for tab "{}"!'.format(subsequent_tab.namepane_txtfield.getText())
                    )
            subsequent_tab.param_handl_combo_cached.removeItemAt(true_index)

    def stateChanged(self, e):
        if e.getSource() == MainTab.mainpane:
            index = MainTab.mainpane.getSelectedIndex()
            if hasattr(self, '_add_sign') and MainTab.mainpane.getTitleAt(index) == self._add_sign:
                MainTab.mainpane.setSelectedIndex(0)
                ConfigTab(self._cph)


class SubTab(JScrollPane, ActionListener):
    BTN_HELP = '?'
    DOCS_URL = 'https://elespike.github.io/burp-cph/'
    INSETS   = Insets(2, 4, 2, 4)
    # Expression pane component indices
    CHECKBOX_INDEX  = 0
    TXT_FIELD_INDEX = 1
    # Socket pane component index tuples
    HTTPS_INDEX = 0
    HOST_INDEX  = 1
    PORT_INDEX  = 3

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
    def set_title_font(component):
        font = Font(Font.SANS_SERIF, Font.BOLD, 14)
        component.setFont(font)
        return component

    def initialize_constraints(self):
        constraints = GridBagConstraints()
        constraints.weightx = 1
        constraints.insets  = self.INSETS
        constraints.fill    = GridBagConstraints.HORIZONTAL
        constraints.anchor  = GridBagConstraints.NORTHWEST
        constraints.gridx   = 0
        constraints.gridy   = 0
        return constraints

    @staticmethod
    def show_card(cardpanel, label):
        cl = cardpanel.getLayout()
        cl.show(cardpanel, label)


    class HelpButton(JButton):
        def __init__(self, title, message, link=''):
            super(JButton, self).__init__()
            self.title   = title
            self.message = JLabel(message)
            self.message.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))

            self.link = SubTab.DOCS_URL
            if link:
                self.link = link

            self.setText(SubTab.BTN_HELP)
            self.setFont(Font(Font.SANS_SERIF, Font.BOLD, 14))

        def show_help(self):
            result = JOptionPane.showOptionDialog(
                self,
                self.message,
                self.title,
                JOptionPane.YES_NO_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                None,
                ['Learn more', 'Close'],
                'Close'
            )
            if result == 0:
                browser_open(self.link)


class OptionsTab(SubTab, ChangeListener):
    VERBOSITY          = 'Verbosity level:'
    BTN_QUICKSAVE      = 'Quicksave'
    BTN_QUICKLOAD      = 'Quickload'
    BTN_EXPORTCONFIG   = 'Export Config'
    BTN_IMPORTCONFIG   = 'Import Config'
    BTN_DOCS           = 'View full guide'
    BTN_EMV            = 'Show EMV'
    CHKBOX_PANE        = 'Tool scope settings'
    QUICKSTART_PANE    = 'Quickstart guide'
    CONFIGNAME_QUICK   = 'quick'
    CONFIGNAME_OPTIONS = 'options'

    def __init__(self, cph):
        SubTab.__init__(self, cph)
        self.loaded_config = odict()

        self.filefilter = FileNameExtensionFilter('JSON', ['json'])

        btn_docs = JButton(self.BTN_DOCS)
        btn_docs.addActionListener(self)

        btn_emv = JButton(self.BTN_EMV)
        btn_emv.addActionListener(self)

        btn_quicksave = JButton(self.BTN_QUICKSAVE)
        btn_quicksave.addActionListener(self)

        btn_quickload = JButton(self.BTN_QUICKLOAD)
        btn_quickload.addActionListener(self)

        btn_exportconfig = JButton(self.BTN_EXPORTCONFIG)
        btn_exportconfig.addActionListener(self)

        btn_importconfig = JButton(self.BTN_IMPORTCONFIG)
        btn_importconfig.addActionListener(self)

        err, warn, info, dbg = 1, 2, 3, 4
        self.verbosity_translator = {
            err : ERROR  ,
            warn: WARNING,
            info: INFO   ,
            dbg : DEBUG  ,
        }

        # TODO load here?
        # options_config = loads(self._cph.callbacks.loadExtensionSetting(OptionsTab.CONFIGNAME_OPTIONS))
        # default_verbosity = options_config.get('default_verbosity')
        # if not default_verbosity:
        default_verbosity = info

        self.verbosity_level_lbl = JLabel(getLevelName(INFO))
        self.verbosity_spinner = JSpinner(SpinnerNumberModel(default_verbosity, err, dbg, 1))
        self.verbosity_spinner.addChangeListener(self)

        verbosity_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        verbosity_pane.add(JLabel(self.VERBOSITY))
        verbosity_pane.add(self.verbosity_spinner)
        verbosity_pane.add(self.verbosity_level_lbl)

        self.emv = JFrame('Effective Modification Viewer')
        self.emv_tab_pane = JTabbedPane()
        self.emv.add(self.emv_tab_pane)

        btn_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        constraints.gridwidth = 2
        btn_pane.add(verbosity_pane, constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        btn_pane.add(btn_quicksave, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_exportconfig, constraints)
        constraints.gridy = 2
        constraints.gridx = 0
        btn_pane.add(btn_quickload, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_importconfig, constraints)
        constraints.gridy = 3
        constraints.gridx = 0
        btn_pane.add(btn_docs, constraints)
        constraints.gridx = 1
        btn_pane.add(btn_emv, constraints)

        # tools_config = options_config.get('tools_config')
        # if not tools_config:
            # tools_config = {
                # 'Proxy'    : True ,
                # 'Target'   : False,
                # 'Spider'   : False,
                # 'Repeater' : True ,
                # 'Sequencer': False,
                # 'Intruder' : False,
                # 'Scanner'  : False,
                # 'Extender' : False,
            # }

        # TODO
        self.chkbox_proxy     = JCheckBox('Proxy'    , True )
        self.chkbox_target    = JCheckBox('Target'   , False)
        self.chkbox_spider    = JCheckBox('Spider'   , False)
        self.chkbox_repeater  = JCheckBox('Repeater' , True )
        self.chkbox_sequencer = JCheckBox('Sequencer', False)
        self.chkbox_intruder  = JCheckBox('Intruder' , False)
        self.chkbox_scanner   = JCheckBox('Scanner'  , False)
        self.chkbox_extender  = JCheckBox('Extender' , False)

        chkbox_pane = JPanel(GridBagLayout())
        chkbox_pane.setBorder(BorderFactory.createTitledBorder(self.CHKBOX_PANE))
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
        quickstart_pane.setBorder(BorderFactory.createTitledBorder(self.QUICKSTART_PANE))
        quickstart_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))
        quickstart_text_lbl = JLabel(CPH_Help.quickstart)
        quickstart_text_lbl.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))
        quickstart_pane.add(quickstart_text_lbl)

        constraints = self.initialize_constraints()
        constraints.gridwidth = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridwidth = 1
        constraints.gridy = 1
        self._main_tab_pane.add(btn_pane, constraints)
        constraints.gridx = 1
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridx = 2
        self._main_tab_pane.add(chkbox_pane, constraints)
        constraints.gridx = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridx = 0
        constraints.gridy = 2
        constraints.gridwidth = 3
        self._main_tab_pane.add(SubTab.create_blank_space(), constraints)
        constraints.gridy = 3
        constraints.weighty = 1
        self._main_tab_pane.add(quickstart_pane, constraints)

    def stateChanged(self, e):
        if e.getSource() == self.verbosity_spinner:
            level = self.verbosity_translator[self.verbosity_spinner.getValue()]
            MainTab.logger.setLevel(level)
            self.verbosity_level_lbl.setText(getLevelName(level))

    def set_tab_values(self, tab, tab_name, config):
        MainTab.set_tab_name(tab, tab_name)
        for cm in tab.config_mechanisms:
            if cm.name in config:
                cm.setter(config[cm.name])
            else:
                MainTab.logger.warning(
                    'Your configuration may have been generated by a previous version of CPH. Expect the unexpected.'
                )
                continue
        # A couple hacks to avoid implementing an ItemListener just for this,
        # because ActionListener doesn't get triggered on setSelected() -_-
        # Reference: https://stackoverflow.com/questions/9882845
        tab.param_handl_forwarder_socket_pane.setVisible(config['enable_forwarder'])
        tab.param_handl_dynamic_pane         .setVisible(config['dynamic_checkbox'])

    def actionPerformed(self, e):
        c = e.getActionCommand()
        if c == self.BTN_QUICKLOAD or c == self.BTN_IMPORTCONFIG:
            replace_config_tabs = False
            result   = 0
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                result = JOptionPane.showOptionDialog(
                    self,
                    'Would you like to Purge or Keep all existing tabs?',
                    'Existing Tabs Detected!',
                    JOptionPane.YES_NO_CANCEL_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    None,
                    ['Purge', 'Keep', 'Cancel'],
                    'Cancel'
                )
            # If purge...
            if result == 0:
                replace_config_tabs = True
                MainTab.logger.info('Replacing configuration...')
            # If not cancel or close dialog...
            # note: result can still be 0 here; do not use 'elif'
            if result != 2 and result != -1:
                if result != 0:
                    MainTab.logger.info('Merging configuration...')

                if c == self.BTN_QUICKLOAD:
                    try:
                        self.loaded_config = loads(
                            self._cph.callbacks.loadExtensionSetting(OptionsTab.CONFIGNAME_QUICK),
                            object_pairs_hook=odict
                        )
                        self.load_config(replace_config_tabs)
                        MainTab.logger.info('Configuration quickloaded.')
                    except StandardError:
                        MainTab.logger.exception('Error during quickload.')

                if c == self.BTN_IMPORTCONFIG:
                    fc = JFileChooser()
                    fc.setFileFilter(self.filefilter)
                    result = fc.showOpenDialog(self)
                    if result == JFileChooser.APPROVE_OPTION:
                        fpath = fc.getSelectedFile().getPath()
                        try:
                            with open(fpath, 'r') as f:
                                self.loaded_config = load(f, object_pairs_hook=odict)
                            self.load_config(replace_config_tabs)
                            MainTab.logger.info('Configuration imported from "{}".'.format(fpath))
                        except StandardError:
                            MainTab.logger.exception('Error importing config from "{}".'.format(fpath))
                    if result == JFileChooser.CANCEL_OPTION:
                        MainTab.logger.info('User canceled configuration import from file.')
            else:
                MainTab.logger.info('User canceled quickload/import.')

        if c == self.BTN_QUICKSAVE:
            try:
                full_config = self.prepare_to_save_all()
                self._cph.callbacks.saveExtensionSetting(OptionsTab.CONFIGNAME_QUICK, dumps(full_config))
                MainTab.logger.info('Configuration quicksaved.')
            except StandardError:
                MainTab.logger.exception('Error during quicksave.')

        if c == self.BTN_DOCS:
            browser_open(self.DOCS_URL)

        if c == self.BTN_EMV:
            if not self.emv.isVisible():
                self.emv.pack()
                self.emv.setSize(800, 600)
                self.emv.show()
            # Un-minimize
            self.emv.setState(JFrame.NORMAL)
            self.emv.toFront()
            for emv_tab in self.emv_tab_pane.getComponents():
                emv_tab.viewer.setDividerLocation(0.5)

        if c == self.BTN_EXPORTCONFIG:
            tabcount = 0
            for tab in MainTab.get_config_tabs():
                tabcount += 1
                break
            if tabcount > 0:
                fc = JFileChooser()
                fc.setFileFilter(self.filefilter)
                result = fc.showSaveDialog(self)
                if result == JFileChooser.APPROVE_OPTION:
                    fpath = fc.getSelectedFile().getPath()
                    if not fpath.endswith('.json'):
                        fpath += '.json'
                    full_config = self.prepare_to_save_all()
                    try:
                        with open(fpath, 'w') as f:
                            dump(full_config, f, indent=4, separators=(',', ': '))
                        MainTab.logger.info('Configuration exported to "{}".'.format(fpath))
                    except IOError:
                        MainTab.logger.exception('Error exporting config to "{}".'.format(fpath))
                if result == JFileChooser.CANCEL_OPTION:
                    MainTab.logger.info('User canceled configuration export to file.')

    def load_config(self, replace_config_tabs):
        loaded_tab_names  = self.loaded_config.keys()
        tabs_left_to_load = list(loaded_tab_names)
        tabs_to_remove    = {}

        # Modify existing and mark for purge where applicable
        for tab_name, tab in product(loaded_tab_names, MainTab.get_config_tabs()):
            if tab_name == tab.namepane_txtfield.getText():
                self.set_tab_values(tab, tab_name, self.loaded_config[tab_name])
                if tab_name in tabs_left_to_load:
                    tabs_left_to_load.remove(tab_name)
                tabs_to_remove[tab] = False
            if tab not in tabs_to_remove:
                tabs_to_remove[tab] = True

        # Import and purge if applicable
        for tab, tab_marked in tabs_to_remove.items():
            if tab_marked and replace_config_tabs:
                MainTab.getOptionsTab().emv_tab_pane.remove(tab.emv_tab)
                MainTab.mainpane.remove(tab)
        for tab_name in tabs_left_to_load:
            self.set_tab_values(ConfigTab(self._cph), tab_name, self.loaded_config[tab_name])

        # No need to proceed if there's only 1 tab.
        # This is also the case when cloning a tab.
        if len(loaded_tab_names) <= 1:
            return

        # Restore tab order
        for tab in MainTab.get_config_tabs():
            tab_name = tab.namepane_txtfield.getText()
            # Adding one because the Options tab is always the first tab.
            if tab_name in loaded_tab_names:
                ConfigTab.move_tab(tab, loaded_tab_names.index(tab_name) + 1)
            else:
                ConfigTab.move_tab(tab, len(loaded_tab_names) + 1)

    def prepare_to_save_all(self):
        MainTab.check_configtab_names()
        full_config = odict()
        for tab in MainTab.get_config_tabs():
            full_config[tab.namepane_txtfield.getText()] = self.prepare_to_save_tab(tab)
        return full_config

    def prepare_to_save_tab(self, tab):
        config = {}
        for cm in tab.config_mechanisms:
            config[cm.name] = cm.getter()
        return config


class EMVTab(JSplitPane, ListSelectionListener):
    MAX_ITEMS = 32
    def __init__(self, configtab):
        self.configtab = configtab
        self.updating = False
        self.selected_index = -1

        self.table = JTable(self.EMVTableModel())
        self.table_model = self.table.getModel()
        sm = self.table.getSelectionModel()
        sm.setSelectionMode(0) # Single selection
        sm.addListSelectionListener(self)

        table_pane = JScrollPane()
        table_pane.setViewportView(self.table)
        table_pane.getVerticalScrollBar().setUnitIncrement(16)

        self.diff_field     = self.configtab._cph.callbacks.createMessageEditor(None, False)
        self.original_field = self.configtab._cph.callbacks.createMessageEditor(None, False)
        self.modified_field = self.configtab._cph.callbacks.createMessageEditor(None, False)

        self.viewer = JSplitPane()
        self.viewer.setLeftComponent(self.original_field.getComponent())
        self.viewer.setRightComponent(self.modified_field.getComponent())

        self.diffpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        # Top pane gets populated in value_changed(), below.
        self.diffpane.setTopComponent(JPanel())
        self.diffpane.setBottomComponent(self.viewer)
        self.diffpane.setDividerLocation(100)

        viewer_pane = JPanel(GridBagLayout())
        constraints = GridBagConstraints()
        constraints.weightx = 1
        constraints.weighty = 1
        constraints.fill    = GridBagConstraints.BOTH
        constraints.anchor  = GridBagConstraints.NORTH
        constraints.gridx   = 0
        constraints.gridy   = 0
        viewer_pane.add(self.diffpane, constraints)

        self.setOrientation(JSplitPane.VERTICAL_SPLIT)
        self.setTopComponent(table_pane)
        self.setBottomComponent(viewer_pane)
        self.setDividerLocation(100)

    def add_table_row(self, time, is_request, original_msg, modified_msg):
        if len(self.table_model.rows) == 0:
            self.viewer.setDividerLocation(0.5)

        message_type = 'Response'
        if is_request:
            message_type = 'Request'
        self.table_model.rows.insert(
            0,
            [str(time)[:-3], message_type, len(modified_msg) - len(original_msg)]
        )
        self.table_model.messages.insert(
            0,
            self.table_model.MessagePair(original_msg, modified_msg)
        )

        if len(self.table_model.rows) > self.MAX_ITEMS:
            self.table_model.rows.pop(-1)
        if len(self.table_model.messages) > self.MAX_ITEMS:
            self.table_model.messages.pop(-1)

        self.table_model.fireTableDataChanged()
        self.table.setRowSelectionInterval(0, 0)

    def valueChanged(self, e):
        # Jenky lock mechanism to prevent crash with many quickly-repeated triggers.
        if self.updating:
            return
        self.updating = True

        index = self.table.getSelectedRow()
        if self.selected_index == index:
            self.updating = False
            return
        self.selected_index = index
        original_msg = self.table_model.messages[index].original_msg
        modified_msg = self.table_model.messages[index].modified_msg

        diff = unified_diff(original_msg.splitlines(1), modified_msg.splitlines(1))
        text = ''
        for line in diff:
            if '---' in line or '+++' in line:
                continue
            text += line
            if not text.endswith('\n'):
                text += '\n'

        dl = self.diffpane.getDividerLocation()
        is_request = self.table_model.rows[index][1] == 'Request'
        self.diff_field    .setMessage(text        , is_request)
        self.original_field.setMessage(original_msg, is_request)
        self.modified_field.setMessage(modified_msg, is_request)

        self.diffpane.setTopComponent(self.diff_field.getComponent().getComponentAt(0))
        self.diffpane.setDividerLocation(dl)
        self.updating = False


    class EMVTableModel(AbstractTableModel):
        def __init__(self):
            super(EMVTab.EMVTableModel, self).__init__()
            self.MessagePair = namedtuple('MessagePair', 'original_msg, modified_msg')
            self.rows = []
            self.messages = []

        def getRowCount(self):
            return len(self.rows)

        def getColumnCount(self):
            return 3

        def getColumnName(self, columnIndex):
            if columnIndex == 0:
                return 'Time'
            if columnIndex == 1:
                return 'Type'
            if columnIndex == 2:
                return 'Length Difference'

        def getValueAt(self, rowIndex, columnIndex):
            return self.rows[rowIndex][columnIndex]

        def setValueAt(self, aValue, rowIndex, columnIndex):
            return

        def isCellEditable(self, rowIndex, columnIndex):
            return False


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
            MainTab.close_tab(MainTab.mainpane.indexOfTabComponent(self.getParent()))

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

        self.addKeyListener(UndoableKeyListener(self))

    def keyReleased(self, e):
        self_index = MainTab.mainpane.getSelectedIndex()
        true_index = self_index - 1 # because of the Options tab
        self.tab_label.setText(self.getText())
        MainTab.getOptionsTab().emv_tab_pane.setTitleAt(true_index, self.getText())
        for i, subsequent_tab in enumerate(MainTab.get_config_tabs()):
            if i <= true_index:
                continue
            subsequent_tab.param_handl_combo_cached.removeItemAt(true_index)
            subsequent_tab.param_handl_combo_cached.insertItemAt(self.getText(), true_index)

    def keyPressed(self, e):
        # Doing self._tab_label.setText() here is sub-optimal. Leave it above.
        pass

    def keyTyped(self, e):
        pass


class UndoableKeyListener(KeyListener):
    REDO = 89
    UNDO = 90
    CTRL = 2
    def __init__(self, target):
        self.undomgr = UndoManager()
        target.getDocument().addUndoableEditListener(self.undomgr)

    def keyReleased(self, e):
        pass

    def keyPressed(self, e):
        if e.getModifiers() == self.CTRL:
            if e.getKeyCode() == self.UNDO and self.undomgr.canUndo():
                self.undomgr.undo()
            if e.getKeyCode() == self.REDO and self.undomgr.canRedo():
                self.undomgr.redo()

    def keyTyped(self, e):
        pass


class ConfigTab(SubTab):
    TXT_FIELD_SIZE = 45
    REGEX          = 'RegEx'
    TAB_NEW_NAME   = 'Unconfigured'

    BTN_BACK     = '<'
    BTN_FWD      = '>'
    BTN_CLONETAB = 'Clone'
    TAB_NAME     = 'Friendly name:'

    # Scope pane
    MSG_MOD_GROUP           = 'Scoping'
    MSG_MOD_SCOPE_BURP      = ' Provided their URLs are within Burp Suite\'s scope,'
    MSG_MOD_TYPES_TO_MODIFY = 'this tab will work'

    MSG_MOD_COMBO_SCOPE_ALL     = 'on all'
    MSG_MOD_COMBO_SCOPE_SOME    = 'only on'
    MSG_MOD_COMBO_SCOPE_CHOICES = [
        MSG_MOD_COMBO_SCOPE_ALL,
        MSG_MOD_COMBO_SCOPE_SOME,
    ]
    MSG_MOD_COMBO_TYPE_REQ     = 'requests'
    MSG_MOD_COMBO_TYPE_RESP    = 'responses'
    MSG_MOD_COMBO_TYPE_BOTH    = 'requests and responses'
    MSG_MOD_COMBO_TYPE_CHOICES = [
        MSG_MOD_COMBO_TYPE_REQ ,
        MSG_MOD_COMBO_TYPE_RESP,
        MSG_MOD_COMBO_TYPE_BOTH,
    ]
    MSG_MOD_SCOPE_SOME = ' containing this expression:'

    # Handling pane
    PARAM_HANDL_GROUP            = 'Parameter handling'
    PARAM_HANDL_AUTO_ENCODE      = 'Automatically URL-encode the first line of the request, if modified'
    PARAM_HANDL_ENABLE_FORWARDER = 'Change the destination of the request'
    PARAM_HANDL_MATCH_EXP        = ' 1) Find matches to this expression:'
    PARAM_HANDL_TARGET           = '2) Target'

    PARAM_HANDL_COMBO_INDICES_FIRST   = 'the first'
    PARAM_HANDL_COMBO_INDICES_EACH    = 'each'
    PARAM_HANDL_COMBO_INDICES_SUBSET  = 'a subset'
    PARAM_HANDL_COMBO_INDICES_CHOICES = [
        PARAM_HANDL_COMBO_INDICES_FIRST ,
        PARAM_HANDL_COMBO_INDICES_EACH  ,
        PARAM_HANDL_COMBO_INDICES_SUBSET,
    ]
    PARAM_HANDL_MATCH_RANGE  = 'of the matches'
    PARAM_HANDL_MATCH_SUBSET = 'Which subset?'
    PARAM_HANDL_ACTION       = ' 3) Replace each target with this expression:'

    PARAM_HANDL_DYNAMIC_CHECKBOX    = 'The value I need is dynamic'
    PARAM_HANDL_DYNAMIC_DESCRIPTION = '4) In the expression above, use named RegEx groups to insert the following:'

    PARAM_HANDL_COMBO_EXTRACT_SINGLE  = 'a value returned by issuing a single request'
    PARAM_HANDL_COMBO_EXTRACT_MACRO   = 'a value returned by issuing a sequence of requests'
    PARAM_HANDL_COMBO_EXTRACT_CACHED  = 'a value in the cached response of a previous CPH tab'
    PARAM_HANDL_COMBO_EXTRACT_CHOICES = [
        PARAM_HANDL_COMBO_EXTRACT_SINGLE,
        PARAM_HANDL_COMBO_EXTRACT_MACRO ,
        PARAM_HANDL_COMBO_EXTRACT_CACHED,
    ]
    PARAM_HANDL_BTN_ISSUE           = 'Issue'
    PARAM_HANDL_EXTRACT_SINGLE      = 'the request in the left pane, then extract the value from its response with this expression:'
    PARAM_HANDL_EXTRACT_MACRO       = 'When invoked from a Session Handling Rule, CPH will extract the value from the final macro response with this expression:'
    PARAM_HANDL_EXTRACT_CACHED_PRE  = 'Extract the value from'
    PARAM_HANDL_EXTRACT_CACHED_POST = '\'s cached response with this expression:'

    CONFIG_MECHANISM  = namedtuple('CONFIG_MECHANISM' , 'name, getter, setter')
    EXPRESSION_CONFIG = namedtuple('EXPRESSION_CONFIG', 'is_regex, expression')
    SOCKET_CONFIG     = namedtuple('SOCKET_CONFIG'    , 'https, host, port')

    def __init__(self, cph, message=None):
        SubTab.__init__(self, cph)

        index = MainTab.mainpane.getTabCount() - 1
        MainTab.mainpane.add(self, index)
        self.tabtitle_pane = ConfigTabTitle()
        MainTab.mainpane.setTabComponentAt(index, self.tabtitle_pane)
        MainTab.mainpane.setSelectedIndex(index)

        btn_back = SubTab.set_title_font(JButton(self.BTN_BACK))
        btn_fwd  = SubTab.set_title_font(JButton(self.BTN_FWD))
        btn_back.addActionListener(self)
        btn_fwd .addActionListener(self)

        btn_clonetab = JButton(self.BTN_CLONETAB)
        btn_clonetab.addActionListener(self)

        controlpane = JPanel(FlowLayout(FlowLayout.LEADING))
        controlpane.add(btn_back)
        controlpane.add(btn_fwd)
        controlpane.add(SubTab.create_blank_space())
        controlpane.add(btn_clonetab)

        namepane = JPanel(FlowLayout(FlowLayout.LEADING))
        namepane.add(SubTab.set_title_font(JLabel(self.TAB_NAME)))
        self.namepane_txtfield = ConfigTabNameField(self.tabtitle_pane.label)
        namepane.add(self.namepane_txtfield)

        msg_mod_layout_pane = JPanel(GridBagLayout())
        msg_mod_layout_pane.setBorder(BorderFactory.createTitledBorder(self.MSG_MOD_GROUP))
        msg_mod_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))

        param_handl_layout_pane = JPanel(GridBagLayout())
        param_handl_layout_pane.setBorder(BorderFactory.createTitledBorder(self.PARAM_HANDL_GROUP))
        param_handl_layout_pane.getBorder().setTitleFont(Font(Font.SANS_SERIF, Font.ITALIC, 16))

        self.msg_mod_combo_scope = JComboBox(self.MSG_MOD_COMBO_SCOPE_CHOICES)
        self.msg_mod_combo_type  = JComboBox(self.MSG_MOD_COMBO_TYPE_CHOICES)
        self.msg_mod_combo_scope.addActionListener(self)
        self.msg_mod_combo_type .addActionListener(self)

        self.msg_mod_exp_pane_scope     = self.create_expression_pane()
        self.msg_mod_exp_pane_scope_lbl = JLabel(self.MSG_MOD_SCOPE_SOME)
        self.msg_mod_exp_pane_scope    .setVisible(False)
        self.msg_mod_exp_pane_scope_lbl.setVisible(False)

        self.param_handl_auto_encode_chkbox      = JCheckBox(self.PARAM_HANDL_AUTO_ENCODE     , False)
        self.param_handl_enable_forwarder_chkbox = JCheckBox(self.PARAM_HANDL_ENABLE_FORWARDER, False)
        self.param_handl_enable_forwarder_chkbox.addActionListener(self)

        self.param_handl_forwarder_socket_pane = self.create_socket_pane()
        self.param_handl_forwarder_socket_pane.setVisible(False)

        self.param_handl_exp_pane_target = self.create_expression_pane()
        self.param_handl_combo_indices = JComboBox(self.PARAM_HANDL_COMBO_INDICES_CHOICES)
        self.param_handl_combo_indices.addActionListener(self)

        self.param_handl_txtfield_match_indices = JTextField(12)
        self.param_handl_txtfield_match_indices.addKeyListener(
            UndoableKeyListener(self.param_handl_txtfield_match_indices)
        )
        self.param_handl_txtfield_match_indices.setText('0')
        self.param_handl_txtfield_match_indices.setEnabled(False)

        self.param_handl_button_indices_help = self.HelpButton(
            CPH_Help.indices.title,
            CPH_Help.indices.message,
            SubTab.DOCS_URL + '#quickstart/indices'
        )
        self.param_handl_button_indices_help.addActionListener(self)

        self.param_handl_subset_pane = JPanel(FlowLayout(FlowLayout.LEADING))

        self.param_handl_dynamic_chkbox = JCheckBox(self.PARAM_HANDL_DYNAMIC_CHECKBOX, False)
        self.param_handl_dynamic_chkbox.addActionListener(self)

        self.param_handl_dynamic_pane = JPanel(GridBagLayout())
        self.param_handl_dynamic_pane.setVisible(False)

        self.param_handl_exp_pane_extract_static = self.create_expression_pane(checked=True, enabled=False)
        self.param_handl_exp_pane_extract_single = self.create_expression_pane(checked=True, enabled=False)
        self.param_handl_exp_pane_extract_macro  = self.create_expression_pane(label=self.PARAM_HANDL_EXTRACT_MACRO, checked=True, enabled=False)
        self.param_handl_exp_pane_extract_cached = self.create_expression_pane(checked=True, enabled=False)

        self.param_handl_issuer_socket_pane = self.create_socket_pane()

        self.request       , self.response        = self.initialize_req_resp()
        self.cached_request, self.cached_response = self.initialize_req_resp()
        if message: # init argument, defaults to None, set when using 'Send to CPH'
            self.request = message.getRequest()
            resp = message.getResponse()
            if resp:
                self.response = resp
            httpsvc = message.getHttpService()
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.HOST_INDEX).setText(httpsvc.getHost())
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.PORT_INDEX).setValue(httpsvc.getPort())
            self.get_socket_pane_component(self.param_handl_issuer_socket_pane, self.HTTPS_INDEX).setSelected(httpsvc.getProtocol() == 'https')
            # Using doClick() since it's initially unchecked, which means it'll get checked *and* the ActionListener will trigger.
            self.param_handl_dynamic_chkbox.doClick()

        self.param_handl_request_editor  = self._cph.callbacks.createMessageEditor(None, True)
        self.param_handl_response_editor = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_request_editor .setMessage(self.request , True)
        self.param_handl_response_editor.setMessage(self.response, False)

        self.param_handl_cached_req_viewer  = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_resp_viewer = self._cph.callbacks.createMessageEditor(None, False)
        self.param_handl_cached_req_viewer .setMessage(self.cached_request , True)
        self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)

        self.param_handl_cardpanel_static_or_extract = JPanel(FlexibleCardLayout())

        self.param_handl_combo_extract = JComboBox(self.PARAM_HANDL_COMBO_EXTRACT_CHOICES)
        self.param_handl_combo_extract.addActionListener(self)

        self.param_handl_button_named_groups_help = self.HelpButton(
            CPH_Help.named_groups.title,
            CPH_Help.named_groups.message,
            SubTab.DOCS_URL + '#quickstart/named_groups'
        )
        self.param_handl_button_named_groups_help.addActionListener(self)

        # These ones don't need ActionListeners; see actionPerformed().
        self.param_handl_button_extract_single_help = self.HelpButton(
            CPH_Help.extract_single.title,
            CPH_Help.extract_single.message,
            SubTab.DOCS_URL + '#quickstart/extract_single'
        )
        self.param_handl_button_extract_macro_help = self.HelpButton(
            CPH_Help.extract_macro.title,
            CPH_Help.extract_macro.message,
            SubTab.DOCS_URL + '#quickstart/extract_macro'
        )
        self.param_handl_button_extract_cached_help = self.HelpButton(
            CPH_Help.extract_cached.title,
            CPH_Help.extract_cached.message,
            SubTab.DOCS_URL + '#quickstart/extract_cached'
        )

        self.param_handl_combo_cached = JComboBox()
        self.param_handl_combo_cached.addActionListener(self)

        self.build_msg_mod_pane(msg_mod_layout_pane)
        self.build_param_handl_pane(param_handl_layout_pane)

        if self.request:
            self.param_handl_combo_extract.setSelectedItem(self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)

        for previous_tab in MainTab.get_config_tabs():
            if previous_tab == self:
                break
            self.param_handl_combo_cached.addItem(previous_tab.namepane_txtfield.getText())

        constraints = self.initialize_constraints()
        constraints.weighty = 0.05
        self._main_tab_pane.add(controlpane, constraints)
        constraints.gridy = 1
        self._main_tab_pane.add(namepane, constraints)
        constraints.gridy = 2
        self._main_tab_pane.add(msg_mod_layout_pane, constraints)
        constraints.gridy = 3
        constraints.weighty = 1
        self._main_tab_pane.add(param_handl_layout_pane, constraints)

        self.emv_tab = EMVTab(self)
        MainTab.getOptionsTab().emv_tab_pane.add(self.namepane_txtfield.getText(), self.emv_tab)

        self.config_mechanisms = [
            ConfigTab.CONFIG_MECHANISM(
                'enabled',
                self.tabtitle_pane.enable_chkbox.isSelected,
                lambda cv: self.tabtitle_pane.enable_chkbox.setSelected(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'modify_scope_choice_index',
                self.msg_mod_combo_scope.getSelectedIndex,
                lambda cv: self.msg_mod_combo_scope.setSelectedIndex(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'modify_type_choice_index',
                self.msg_mod_combo_type.getSelectedIndex,
                lambda cv: self.msg_mod_combo_type.setSelectedIndex(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'modify_expression',
                lambda   : self.get_exp_pane_config(self.msg_mod_exp_pane_scope    ),
                lambda cv: self.set_exp_pane_config(self.msg_mod_exp_pane_scope, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'auto_encode',
                self.param_handl_auto_encode_chkbox.isSelected,
                lambda cv: self.param_handl_auto_encode_chkbox.setSelected(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'enable_forwarder',
                self.param_handl_enable_forwarder_chkbox.isSelected,
                lambda cv: self.param_handl_enable_forwarder_chkbox.setSelected(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'forwarder',
                lambda   : self.get_socket_pane_config(self.param_handl_forwarder_socket_pane    ),
                lambda cv: self.set_socket_pane_config(self.param_handl_forwarder_socket_pane, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'match_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_target    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_target, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'indices_choice_index',
                self.param_handl_combo_indices.getSelectedIndex,
                lambda cv: self.param_handl_combo_indices.setSelectedIndex(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'extract_choice_index',
                self.param_handl_combo_extract.getSelectedIndex,
                lambda cv: self.param_handl_combo_extract.setSelectedIndex(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'match_indices',
                self.param_handl_txtfield_match_indices.getText,
                lambda cv: self.param_handl_txtfield_match_indices.setText(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'static_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_static    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_static, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'dynamic_checkbox',
                self.param_handl_dynamic_chkbox.isSelected,
                lambda cv: self.param_handl_dynamic_chkbox.setSelected(cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'single_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_single    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_single, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'issuer',
                lambda   : self.get_socket_pane_config(self.param_handl_issuer_socket_pane    ),
                lambda cv: self.set_socket_pane_config(self.param_handl_issuer_socket_pane, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'single_request',
                lambda   : self._cph.helpers.bytesToString(self.param_handl_request_editor.getMessage()),
                lambda cv: self.param_handl_request_editor.setMessage(self._cph.helpers.stringToBytes(cv), True)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'single_response',
                lambda   : self._cph.helpers.bytesToString(self.param_handl_response_editor.getMessage()),
                lambda cv: self.param_handl_response_editor.setMessage(self._cph.helpers.stringToBytes(cv), False)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'macro_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_macro    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_macro, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'cached_expression',
                lambda   : self.get_exp_pane_config(self.param_handl_exp_pane_extract_cached    ),
                lambda cv: self.set_exp_pane_config(self.param_handl_exp_pane_extract_cached, cv)
            ),
            ConfigTab.CONFIG_MECHANISM(
                'cached_selection',
                self.param_handl_combo_cached.getSelectedItem,
                lambda cv: self.param_handl_combo_cached.setSelectedItem(cv)
            ),
        ]

    def initialize_req_resp(self):
        return [], self._cph.helpers.stringToBytes(''.join([' \r\n' for i in range(6)]))

    def create_expression_pane(self, label=None, checked=False, enabled=True):
        field = JTextField()
        field.setColumns(self.TXT_FIELD_SIZE)

        field.addKeyListener(UndoableKeyListener(field))

        box = JCheckBox(self.REGEX, checked)
        if not enabled:
            box.setEnabled(False)

        child_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        child_pane.add(box)
        child_pane.add(field)

        parent_pane = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        if label:
            parent_pane.add(JLabel(label), constraints)
            constraints.gridy += 1
        parent_pane.add(child_pane, constraints)

        return parent_pane

    def create_socket_pane(self):
        host_field = JTextField()
        host_field.setColumns(int(self.TXT_FIELD_SIZE * 0.75))
        host_field.setText('host')
        host_field.addKeyListener(UndoableKeyListener(host_field))

        port_spinner = JSpinner(SpinnerNumberModel(80, 0, 65535, 1))
        port_spinner.setEditor(JSpinner.NumberEditor(port_spinner, '#'))

        socket_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        https_box = JCheckBox('HTTPS')
        https_box.setSelected(False)
        socket_pane.add(https_box   )
        socket_pane.add(host_field  )
        socket_pane.add(JLabel(':') )
        socket_pane.add(port_spinner)

        return socket_pane

    def get_exp_pane_component(self, pane, component_index):
        """
        component_index values:
        0: regex checkbox
        1: expression field
        See create_expression_pane() for further details
        """
        comp_count = pane.getComponentCount()
        if comp_count == 1:
            # then there's no label and child_pane is the only component
            child_pane = pane.getComponent(0)
        elif comp_count == 2:
            # then there is a label and child_pane is the second component
            child_pane = pane.getComponent(1)
        return child_pane.getComponent(component_index)

    def get_exp_pane_expression(self, pane):
        expression = self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).getText()
        # If the RegEx checkbox is unchecked, run re.escape()
        # in order to treat it like a literal string.
        if not self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX).isSelected():
            expression = re_escape(expression)
        return expression

    def get_exp_pane_config(self, pane):
        config = self.EXPRESSION_CONFIG(
            self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX).isSelected(),
            self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).getText()
        )
        return config

    def set_exp_pane_config(self, pane, config):
        config = self.EXPRESSION_CONFIG(*config)
        self.get_exp_pane_component(pane, ConfigTab.CHECKBOX_INDEX ).setSelected(config.is_regex  )
        self.get_exp_pane_component(pane, ConfigTab.TXT_FIELD_INDEX).setText    (config.expression)

    def get_socket_pane_component(self, pane, component_index):
        """
        indices_tuple values:
        0: https checkbox
        1: host field
        3: port spinner (2 is the ':' JLabel)
        See create_socket_pane() for further details
        """
        return pane.getComponent(component_index)

    def get_socket_pane_config(self, pane):
        config = self.SOCKET_CONFIG(
            self.get_socket_pane_component(pane, ConfigTab.HTTPS_INDEX).isSelected(),
            self.get_socket_pane_component(pane, ConfigTab.HOST_INDEX ).getText   (),
            self.get_socket_pane_component(pane, ConfigTab.PORT_INDEX ).getValue  ()
        )
        return config

    def set_socket_pane_config(self, pane, config):
        config = self.SOCKET_CONFIG(*config)
        self.get_socket_pane_component(pane, ConfigTab.HTTPS_INDEX).setSelected(config.https)
        self.get_socket_pane_component(pane, ConfigTab.HOST_INDEX ).setText    (config.host )
        self.get_socket_pane_component(pane, ConfigTab.PORT_INDEX ).setValue   (config.port )

    def build_msg_mod_pane(self, msg_mod_pane):
        msg_mod_req_or_resp_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        msg_mod_req_or_resp_pane.add(JLabel(self.MSG_MOD_TYPES_TO_MODIFY))
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_scope)
        msg_mod_req_or_resp_pane.add(self.msg_mod_combo_type)
        msg_mod_req_or_resp_pane.add(self.msg_mod_exp_pane_scope_lbl)

        constraints = self.initialize_constraints()
        msg_mod_pane.add(SubTab.set_title_font(JLabel(self.MSG_MOD_SCOPE_BURP)), constraints)
        constraints.gridy = 1
        msg_mod_pane.add(msg_mod_req_or_resp_pane, constraints)
        constraints.gridy = 2
        msg_mod_pane.add(self.msg_mod_exp_pane_scope, constraints)

    def build_param_handl_pane(self, param_derivation_pane):
        target_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        target_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_TARGET)))
        target_pane.add(self.param_handl_combo_indices)
        target_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_MATCH_RANGE)))

        self.param_handl_subset_pane.add(JLabel(self.PARAM_HANDL_MATCH_SUBSET))
        self.param_handl_subset_pane.add(self.param_handl_txtfield_match_indices)
        self.param_handl_subset_pane.add(self.param_handl_button_indices_help)
        self.param_handl_subset_pane.setVisible(False)

        derive_param_single_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        derive_param_single_card.add(self.param_handl_issuer_socket_pane, constraints)
        constraints.gridy = 1
        issue_request_pane   = JPanel(FlowLayout(FlowLayout.LEADING))
        issue_request_button = JButton(self.PARAM_HANDL_BTN_ISSUE)
        issue_request_button.addActionListener(self)
        issue_request_pane.add(issue_request_button)
        issue_request_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_SINGLE))
        derive_param_single_card.add(issue_request_pane, constraints)
        constraints.gridy = 2
        derive_param_single_card.add(self.param_handl_exp_pane_extract_single, constraints)
        constraints.gridy = 3
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent (self.param_handl_request_editor .getComponent())
        splitpane.setRightComponent(self.param_handl_response_editor.getComponent())
        derive_param_single_card.add(splitpane, constraints)
        splitpane.setDividerLocation(0.5)

        derive_param_macro_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        derive_param_macro_card.add(self.param_handl_exp_pane_extract_macro, constraints)

        cached_param_card = JPanel(GridBagLayout())
        constraints = self.initialize_constraints()
        tab_choice_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_CACHED_PRE))
        tab_choice_pane.add(self.param_handl_combo_cached)
        tab_choice_pane.add(JLabel(self.PARAM_HANDL_EXTRACT_CACHED_POST))
        cached_param_card.add(tab_choice_pane, constraints)
        constraints.gridy = 1
        cached_param_card.add(self.param_handl_exp_pane_extract_cached, constraints)
        constraints.gridy = 2
        constraints.gridwidth = 2
        splitpane = JSplitPane()
        splitpane.setLeftComponent (self.param_handl_cached_req_viewer .getComponent())
        splitpane.setRightComponent(self.param_handl_cached_resp_viewer.getComponent())
        cached_param_card.add(splitpane, constraints)
        splitpane.setDividerLocation(0.5)

        self.param_handl_cardpanel_static_or_extract.add(derive_param_single_card, self.PARAM_HANDL_COMBO_EXTRACT_SINGLE)
        self.param_handl_cardpanel_static_or_extract.add(derive_param_macro_card , self.PARAM_HANDL_COMBO_EXTRACT_MACRO )
        self.param_handl_cardpanel_static_or_extract.add(cached_param_card       , self.PARAM_HANDL_COMBO_EXTRACT_CACHED)

        # Making a FlowLayout panel here so the combo box doesn't stretch.
        combo_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        combo_pane.add(self.param_handl_combo_extract)
        placeholder_btn = self.HelpButton('', '')
        placeholder_btn.addActionListener(self)
        combo_pane.add(placeholder_btn)
        combo_pane.add(SubTab.create_blank_space())
        constraints = self.initialize_constraints()
        dyn_desc_pane = JPanel(FlowLayout(FlowLayout.LEADING))
        dyn_desc_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_DYNAMIC_DESCRIPTION)))
        dyn_desc_pane.add(self.param_handl_button_named_groups_help)
        self.param_handl_dynamic_pane.add(dyn_desc_pane, constraints)
        constraints.gridy = 1
        self.param_handl_dynamic_pane.add(combo_pane, constraints)
        constraints.gridy = 2
        constraints.gridwidth = GridBagConstraints.REMAINDER - 1
        self.param_handl_dynamic_pane.add(self.param_handl_cardpanel_static_or_extract, constraints)

        constraints = self.initialize_constraints()
        param_derivation_pane.add(self.param_handl_auto_encode_chkbox, constraints)
        constraints.gridy = 1
        param_derivation_pane.add(self.param_handl_enable_forwarder_chkbox, constraints)
        constraints.gridy = 2
        param_derivation_pane.add(self.param_handl_forwarder_socket_pane, constraints)
        constraints.gridy = 3
        param_derivation_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_MATCH_EXP)), constraints)
        constraints.gridy = 4
        param_derivation_pane.add(self.param_handl_exp_pane_target, constraints)
        constraints.gridy = 5
        param_derivation_pane.add(target_pane, constraints)
        constraints.gridy = 6
        param_derivation_pane.add(self.param_handl_subset_pane, constraints)
        constraints.gridy = 7
        param_derivation_pane.add(SubTab.set_title_font(JLabel(self.PARAM_HANDL_ACTION)), constraints)
        constraints.gridy = 8
        param_derivation_pane.add(self.param_handl_exp_pane_extract_static, constraints)
        constraints.gridy = 9
        param_derivation_pane.add(self.param_handl_dynamic_chkbox, constraints)
        constraints.gridy = 10
        param_derivation_pane.add(self.param_handl_dynamic_pane, constraints)

    @staticmethod
    def restore_combo_cached_selection(tab, selected_item):
        tab.param_handl_combo_cached.setSelectedItem(selected_item)
        # If the item has been removed, remove selection.
        if tab.param_handl_combo_cached.getSelectedItem() != selected_item:
            tab.param_handl_combo_cached.setSelectedItem(None)
            if tab.param_handl_combo_extract.getSelectedItem() == ConfigTab.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                MainTab.logger.warning(
                    'Selected cache no longer available for tab "{}"!'.format(tab.namepane_txtfield.getText())
                )

    @staticmethod
    def move_tab(tab, desired_index):
        # The Options tab is index 0, hence subtracting 1 in a number of lines below.
        if desired_index <= 0 or desired_index >= MainTab.mainpane.getTabCount() - 1:
            return

        MainTab.mainpane.setSelectedIndex(0)
        emv_sel_tab = MainTab.getOptionsTab().emv_tab_pane.getSelectedComponent()
        current_index = MainTab.mainpane.indexOfComponent(tab)
        combo_cached_item = tab.param_handl_combo_cached.getSelectedItem()

        if current_index > desired_index:
            MainTab.mainpane.add(tab, desired_index)
            MainTab.getOptionsTab().emv_tab_pane.add(tab.emv_tab, desired_index - 1)
            # Rearrange combo_cached appropriately.
            for i, other_tab in enumerate(MainTab.get_config_tabs()):
                if i < desired_index - 1:
                    continue
                selected_item = other_tab.param_handl_combo_cached.getSelectedItem()
                if i > desired_index - 1 and i <= current_index - 1:
                    tab.param_handl_combo_cached.removeItemAt(tab.param_handl_combo_cached.getItemCount() - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                if i > current_index - 1:
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                ConfigTab.restore_combo_cached_selection(other_tab, selected_item)

        else:
            # I've no idea why +1 is needed here. =)
            MainTab.mainpane.add(tab, desired_index + 1)
            MainTab.getOptionsTab().emv_tab_pane.add(tab.emv_tab, desired_index)
            # Rearrange combo_cached appropriately.
            for i, other_tab in enumerate(MainTab.get_config_tabs()):
                if i < current_index - 1:
                    continue
                selected_item = other_tab.param_handl_combo_cached.getSelectedItem()
                if i < desired_index - 1:
                    tab.param_handl_combo_cached.insertItemAt(other_tab.namepane_txtfield.getText(), i)
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                if i > desired_index - 1:
                    other_tab.param_handl_combo_cached.removeItemAt(current_index - 1)
                    other_tab.param_handl_combo_cached.insertItemAt(tab.namepane_txtfield.getText(), desired_index - 1)
                ConfigTab.restore_combo_cached_selection(other_tab, selected_item)

        MainTab.mainpane.setTabComponentAt(desired_index, tab.tabtitle_pane)
        MainTab.mainpane.setSelectedIndex (desired_index)
        MainTab.getOptionsTab().emv_tab_pane.setTitleAt(
            desired_index - 1,
            tab.namepane_txtfield.getText()
        )
        MainTab.getOptionsTab().emv_tab_pane.setSelectedComponent(emv_sel_tab)
        ConfigTab.restore_combo_cached_selection(tab, combo_cached_item)

    @staticmethod
    def move_tab_back(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() - 1
        ConfigTab.move_tab(tab, desired_index)

    @staticmethod
    def move_tab_fwd(tab):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1
        ConfigTab.move_tab(tab, desired_index)

    def clone_tab(self):
        desired_index = MainTab.mainpane.getSelectedIndex() + 1

        newtab = ConfigTab(self._cph)
        MainTab.set_tab_name(newtab, self.namepane_txtfield.getText())
        config = MainTab.getOptionsTab().prepare_to_save_tab(self)
        MainTab.getOptionsTab().loaded_config = {self.namepane_txtfield.getText(): config}
        MainTab.getOptionsTab().load_config(False)

        ConfigTab.move_tab(newtab, desired_index)

    # def disable_cache_viewers(self):
        # self.cached_request, self.cached_response = self.initialize_req_resp()
        # self.param_handl_cached_req_viewer .setMessage(self.cached_request , False)
        # self.param_handl_cached_resp_viewer.setMessage(self.cached_response, False)

    # @staticmethod
    # def disable_all_cache_viewers():
        # for tab in MainTab.mainpane.getComponents():
            # if isinstance(tab, ConfigTab):
                # tab.disable_cache_viewers()

    def actionPerformed(self, e):
        c = e.getActionCommand()

        if c == self.BTN_HELP:
            source = e.getSource()
            if hasattr(source, 'title') and source.title:
                source.show_help()
            else:
                # The dynamic help button (placeholder_btn) has no title,
                # so use the selected combobox item to show the appropriate help message.
                extract_combo_selection = self.param_handl_combo_extract.getSelectedItem()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_SINGLE:
                    self.param_handl_button_extract_single_help.show_help()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_MACRO:
                    self.param_handl_button_extract_macro_help.show_help()
                if extract_combo_selection == self.PARAM_HANDL_COMBO_EXTRACT_CACHED:
                    self.param_handl_button_extract_cached_help.show_help()

        if c == 'comboBoxChanged':
            c = e.getSource().getSelectedItem()

        if c == self.MSG_MOD_COMBO_TYPE_RESP:
            self.param_handl_auto_encode_chkbox     .setVisible(False)
            self.param_handl_enable_forwarder_chkbox.setVisible(False)
            self.param_handl_forwarder_socket_pane  .setVisible(False)
        elif c == self.MSG_MOD_COMBO_TYPE_REQ or c == self.MSG_MOD_COMBO_TYPE_BOTH:
            self.param_handl_auto_encode_chkbox     .setVisible(True)
            self.param_handl_enable_forwarder_chkbox.setVisible(True)
            self.param_handl_forwarder_socket_pane  .setVisible(self.param_handl_enable_forwarder_chkbox.isSelected())

        if c == self.MSG_MOD_COMBO_SCOPE_ALL:
            self.msg_mod_exp_pane_scope_lbl.setVisible(False)
            self.msg_mod_exp_pane_scope.setVisible(False)
        if c == self.MSG_MOD_COMBO_SCOPE_SOME:
            self.msg_mod_exp_pane_scope_lbl.setVisible(True)
            self.msg_mod_exp_pane_scope.setVisible(True)

        if c == self.PARAM_HANDL_ENABLE_FORWARDER:
            self.param_handl_forwarder_socket_pane.setVisible(self.param_handl_enable_forwarder_chkbox.isSelected())

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

        if c == self.PARAM_HANDL_DYNAMIC_CHECKBOX:
            is_selected = self.param_handl_dynamic_chkbox.isSelected()
            self.param_handl_dynamic_pane.setVisible(is_selected)

        if c in self.PARAM_HANDL_COMBO_EXTRACT_CHOICES:
            SubTab.show_card(self.param_handl_cardpanel_static_or_extract, c)

        # Set the cached request/response viewers to the selected tab's cache
        if e.getSource() == self.param_handl_combo_cached:
            if c is None:
                req, resp = self.initialize_req_resp()
            if c in MainTab.get_config_tab_names():
                req, resp = MainTab.get_config_tab_cache(c)
            self.param_handl_cached_req_viewer .setMessage(req , True)
            self.param_handl_cached_resp_viewer.setMessage(resp, False)

        if c == self.PARAM_HANDL_BTN_ISSUE:
            start_new_thread(self._cph.issue_request, (self,))

        if c == self.BTN_BACK:
            ConfigTab.move_tab_back(self)
        if c == self.BTN_FWD:
            ConfigTab.move_tab_fwd(self)
        if c == self.BTN_CLONETAB:
            self.clone_tab()


class FlexibleCardLayout(CardLayout):
    def __init__(self):
        super(FlexibleCardLayout, self).__init__()

    def preferredLayoutSize(self, parent):
        current = FlexibleCardLayout.find_current_component(parent)
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

