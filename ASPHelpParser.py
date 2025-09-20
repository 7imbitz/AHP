# -*- coding: utf-8 -*-

import re
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (
    JPanel, JScrollPane, JTable, 
    JMenuItem, JLabel, JSplitPane
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.util import ArrayList
from java.awt import BorderLayout, Color, Desktop
from java.awt.event import MouseAdapter
from java.net import URI
from java.lang import Integer, String

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension and set up the UI"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ASPHelpParser")

        # Single source of truth for parsed entries
        self._rows = []

        # Build full UI
        self._setupUI()

        callbacks.addSuiteTab(self)
        callbacks.registerContextMenuFactory(self)
        
        print("[AHP] ASPHelpParser Extension loaded Successfully!")

    def _setupUI(self):
        """Create and configure the main user interface"""
        self._mainPanel = JPanel(BorderLayout())

        # Create horizontal split pane
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        splitPane.setResizeWeight(0.5)

        # Left panel - table
        leftPanel = self._createTablePanel()
        splitPane.setLeftComponent(leftPanel)

        # Right panel - request/response viewers
        rightPanel = self._createViewerPanel()
        splitPane.setRightComponent(rightPanel)

        self._mainPanel.add(splitPane, BorderLayout.CENTER)

    def _createTablePanel(self):
        """Create the table panel showing API endpoints"""
        panel = JPanel(BorderLayout())
        self._tablePanel = AHPTablePanel(self._rows, self)  # pass extender
        panel.add(self._tablePanel, BorderLayout.CENTER)
        return panel

    def _createViewerPanel(self):
        """Create request/response viewers"""
        panel = JPanel(BorderLayout())

        # Split vertically (top = request, bottom = response)
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.5)

        # Burp provides text editors for request/response
        self._requestViewer = self._callbacks.createMessageEditor(None, False)
        requestPanel = JPanel(BorderLayout())
        requestPanel.add(JLabel("Request"), BorderLayout.NORTH)
        requestPanel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        splitPane.setTopComponent(requestPanel)
        
        self._responseViewer = self._callbacks.createMessageEditor(None, False)
        responsePanel = JPanel(BorderLayout())
        responsePanel.add(JLabel("Response"), BorderLayout.NORTH)
        responsePanel.add(self._responseViewer.getComponent(), BorderLayout.CENTER)
        splitPane.setBottomComponent(responsePanel)

        panel.add(splitPane, BorderLayout.CENTER)
        return panel

    def getTabCaption(self):
        return "AHP"

    def getUiComponent(self):
        return self._mainPanel

    def createMenuItems(self, invocation):
        items = ArrayList()
        selected = invocation.getSelectedMessages()
        if not selected:
            return items

        menu_item = JMenuItem("Send to AHP")

        def on_menu(event, msgs=selected):
            msg = msgs[0]
            response = msg.getResponse()
            if not response:
                return

            analyzed_req = self._helpers.analyzeRequest(msg)
            url_req = analyzed_req.getUrl()
            print("[AHP] Parsing {}".format(url_req))
            analyzed = self._helpers.analyzeResponse(response)
            body = response[analyzed.getBodyOffset():].tostring()

            matches = re.findall(r'<a\s+href="([^"]+)">([^<]+)</a>', body)
            if not matches:
                return

            svc = msg.getHttpService()
            proto = "https" if svc.getPort() == 443 else "http"
            host = svc.getHost()

            for href, text in matches:
                parts = text.strip().split(" ", 1)
                method, url = (parts[0], parts[1]) if len(parts) == 2 else ("?", text.strip())
                full_ref = "{}://{}/{}".format(proto, host, href.lstrip("/"))

                entry = {
                    "method": method,
                    "url": "{}://{}/{}".format(proto, host, url.lstrip("/")),
                    "reference": full_ref
                }

                # Skip unwanted entries
                if method == "?" and ("API" in url.upper() or "HOME" in url.upper()):
                    continue

                # Deduplicate
                if entry not in self._rows:
                    self._rows.append(entry)


            # Tell the table model data has changed
            self._tablePanel._tableModel.fireTableDataChanged()

        menu_item.addActionListener(on_menu)
        items.add(menu_item)
        return items


# --- Custom Renderer for clickable Reference column ---
class LinkCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        label = JLabel("{}".format(value))
        if isSelected:
            label.setForeground(table.getSelectionForeground())
            label.setBackground(table.getSelectionBackground())
            label.setOpaque(True)
        else:
            label.setForeground(Color.BLUE)
        return label


# --- Table Model ---
class AHPTableModel(AbstractTableModel):
    def __init__(self, log):
        self._log = log
        self._columnNames = ["ID", "Method", "URL", "Reference"]

    def getRowCount(self):
        return len(self._log)

    def getColumnCount(self):
        return len(self._columnNames)

    def getColumnName(self, columnIndex):
        return self._columnNames[columnIndex]

    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log[rowIndex]
        if columnIndex == 0:
            return Integer(rowIndex + 1)
        elif columnIndex == 1:
            return logEntry["method"]
        elif columnIndex == 2:
            return logEntry["url"]
        elif columnIndex == 3:
            return logEntry["reference"]
        return ""

    def getColumnClass(self, columnIndex):
        if columnIndex == 0:
            return Integer
        return String


# --- Table Panel ---
class AHPTablePanel(JPanel):
    def __init__(self, log, extender):
        JPanel.__init__(self, BorderLayout())
        self._log = log
        self._tableModel = AHPTableModel(self._log)
        self._table = JTable(self._tableModel)

        # Enable sorting
        self._table.setAutoCreateRowSorter(True)

        # Add selection listener
        self._table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(extender, self._table)
        )
        
        # Set column widths
        columnModel = self._table.getColumnModel()
        columnModel.getColumn(0).setPreferredWidth(30)   # ID
        columnModel.getColumn(1).setPreferredWidth(40)   # Method
        columnModel.getColumn(2).setPreferredWidth(350)  # URL (increased)
        columnModel.getColumn(3).setPreferredWidth(450)  # Reference (increased)


        # Set custom renderer for Reference column
        self._table.getColumn("Reference").setCellRenderer(LinkCellRenderer())

        # Add mouse listener for clickable links
        self._table.addMouseListener(self.ClickHandler(self))

        scrollPane = JScrollPane(self._table)
        self.add(scrollPane, BorderLayout.CENTER)

    class ClickHandler(MouseAdapter):
        def __init__(self, parent):
            self.parent = parent

        def mouseClicked(self, event):
            table = event.getSource()
            row = table.rowAtPoint(event.getPoint())
            col = table.columnAtPoint(event.getPoint())
            if col == 3:  # Reference column
                value = table.getValueAt(row, col)
                try:
                    Desktop.getDesktop().browse(URI(value))
                except Exception as e:
                    print("[AHP] Failed to open link:", e)


class TableSelectionListener(ListSelectionListener):
    def __init__(self, extender, table):
        self._extender = extender
        self._table = table

    def valueChanged(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._table.getSelectedRow()
        if row < 0:
            return

        # Convert from view → model index (because sorting is enabled)
        row = self._table.convertRowIndexToModel(row)
        entry = self._extender._rows[row]

        # Build a "skeleton" HTTP request
        method = entry["method"]
        url = entry["url"]

        host = url.split("://", 1)[1].split("/", 1)[0]
        path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"

        request_bytes = "{} {} HTTP/1.1\r\nHost: {}\r\n\r\n".format(
            method, path, host
        ).encode("utf-8")

        self._extender._requestViewer.setMessage(request_bytes, True)
        self._extender._responseViewer.setMessage(b"", False)