from burp import IBurpExtender, ITab
from javax.swing import JPanel, JLabel, BoxLayout

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("ASPHelpParser")

        # create UI
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.panel.add(JLabel("Hello Burp! This is my custom tab."))

        # register tab
        self.callbacks.addSuiteTab(self)

        # also print to output tab
        print("Hello Burp! Extension AHP loaded successfully.")

    # ITab interface
    def getTabCaption(self):
        return "AHP"

    def getUiComponent(self):
        return self.panel


