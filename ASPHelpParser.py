# -*- coding: utf-8 -*-

import re, threading, HTMLParser
from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (
    JPanel, JScrollPane, JTable, 
    JMenuItem, JLabel, JSplitPane, SwingUtilities,
    KeyStroke, AbstractAction, JComponent, JPopupMenu
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer
from java.util import ArrayList
from java.awt import BorderLayout, Color, Desktop, Toolkit, Cursor, Font
from java.awt.event import MouseAdapter, KeyEvent, InputEvent, ActionListener
from java.net import URI, URL
from java.lang import Integer, String
from java.awt.font import TextAttribute

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        """Initialize the extension and set up the UI"""
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ASPHelpParser")

        self._rows = []

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
        
        # Add context popup item to the table
        # popup = JPopupMenu()
        # sendRequestMenu = JMenuItem("Send Crafted Request to Repeater")
        # sendRequestMenu.addActionListener(SendRequestRepeater(self, True))   # True => use original requestResponse
        # popup.add(sendRequestMenu)
        # # attach popup to JTable component
        # self._tablePanel._table.setComponentPopupMenu(popup)

        # # Bind Cmd/Ctrl+R to the table
        # # get table input/action maps
        # try:
        #     menu_mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx()
        #     key_stroke = KeyStroke.getKeyStroke(KeyEvent.VK_R, menu_mask)
        # except Exception:
        #     key_stroke = KeyStroke.getKeyStroke(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK)

        # inputMap = self._tablePanel._table.getInputMap(JComponent.WHEN_FOCUSED)
        # actionMap = self._tablePanel._table.getActionMap()
        # inputMap.put(key_stroke, "AHP_SEND_TO_REPEATER")
        # actionMap.put("AHP_SEND_TO_REPEATER", SendRequestToRepeaterAction(self))

        self._mainPanel.add(splitPane, BorderLayout.CENTER)

    def _createTablePanel(self):
        """Create the table panel showing API endpoints"""
        panel = JPanel(BorderLayout())
        self._tablePanel = AHPTablePanel(self._rows, self) 
        panel.add(self._tablePanel, BorderLayout.CENTER)
        return panel

    def _createViewerPanel(self):
        """Create request/response viewers"""
        panel = JPanel(BorderLayout())

        # Split vertically (top = request, bottom = response)
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.5)

        self._requestViewer = self._callbacks.createMessageEditor(None, False)
        requestPanel = JPanel(BorderLayout())
        requestPanel.add(JLabel("Expected Request"), BorderLayout.NORTH)
        requestPanel.add(self._requestViewer.getComponent(), BorderLayout.CENTER)
        splitPane.setTopComponent(requestPanel)
        
        self._responseViewer = self._callbacks.createMessageEditor(None, False)
        responsePanel = JPanel(BorderLayout())
        responsePanel.add(JLabel("Expected Response"), BorderLayout.NORTH)
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
            # Exact <a> markers for API Information
            matches = re.findall(r'<a\s+href="([^"]+)">([^<]+)</a>', body)
            if not matches:
                return

            svc = msg.getHttpService()
            proto = "https" if svc.getPort() == 443 else "http"
            host = svc.getHost()

            html_parser = HTMLParser.HTMLParser()

            for href, text in matches:
                parts = text.strip().split(" ", 1)
                method, url = (parts[0], parts[1]) if len(parts) == 2 else ("?", text.strip())
                url = html_parser.unescape(url)
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

            self._tablePanel._tableModel.fireTableDataChanged()

        menu_item.addActionListener(on_menu)
        items.add(menu_item)
        return items

class LinkCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        label = JLabel(value)

        # Get current font and add underline attribute
        font = label.getFont()
        attrs = font.getAttributes()
        attrs[TextAttribute.UNDERLINE] = TextAttribute.UNDERLINE_ON
        label.setFont(Font(font.getName(), font.getStyle(), font.getSize()).deriveFont(attrs))

        if isSelected:
            label.setForeground(table.getSelectionForeground())
            label.setBackground(table.getSelectionBackground())
            label.setOpaque(True)
        else:
            label.setForeground(Color.BLUE)

        label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        return label

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

class AHPTablePanel(JPanel):
    def __init__(self, log, extender):
        JPanel.__init__(self, BorderLayout())
        self._log = log
        self._tableModel = AHPTableModel(self._log)
        self._table = JTable(self._tableModel)

        self._table.setAutoCreateRowSorter(True)

        self._table.getSelectionModel().addListSelectionListener(
            TableSelectionListener(extender, self._table)
        )
        
        columnModel = self._table.getColumnModel()
        columnModel.getColumn(0).setPreferredWidth(30)   # ID
        columnModel.getColumn(1).setPreferredWidth(40)   # Method
        columnModel.getColumn(2).setPreferredWidth(350)  # URL (increased)
        columnModel.getColumn(3).setPreferredWidth(450)  # Reference (increased)

        self._table.getColumn("Reference").setCellRenderer(LinkCellRenderer())

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
            if col == 3:  
                value = table.getValueAt(row, col)
                try:
                    Desktop.getDesktop().browse(URI(value))
                except Exception as e:
                    print("[AHP] Failed to open link:", e)

html_parser = HTMLParser.HTMLParser()

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

        row = self._table.convertRowIndexToModel(row)
        entry = self._extender._rows[row]

        worker = threading.Thread(target=self._processSelection, args=(entry,))
        worker.daemon = True
        worker.start()

    def _processSelection(self, entry):
        try:
            request_bytes, response_bytes = self._buildRequestAndResponseFromEntry(entry)
        except Exception as e:
            print("[AHP] Worker error:", e)
            request_bytes = None
            response_bytes = None

        def update_viewers():
            try:
                if request_bytes is not None:
                    self._extender._requestViewer.setMessage(request_bytes, True)
                if response_bytes is not None:
                    self._extender._responseViewer.setMessage(response_bytes, False)
                else:
                    self._extender._responseViewer.setMessage(b"", False)
            except Exception as e:
                print("[AHP] Failed to update viewers:", e)

        SwingUtilities.invokeLater(update_viewers)

    def _buildRequestAndResponseFromEntry(self, entry):
        """
        Returns (request_bytes, response_bytes_or_None)
        """

        method = entry.get("method", "GET").upper()
        url = entry.get("url", "")
        reference = entry.get("reference", "")

        # Parse host/path from the main url
        try:
            u_main = URL(url)
            target_host = u_main.getHost()
            target_path = u_main.getPath() or "/"
            if u_main.getQuery():
                target_path += "?" + u_main.getQuery()
        except Exception:
            if "://" in url:
                target_host = url.split("://", 1)[1].split("/", 1)[0]
            else:
                target_host = ""
            target_path = "/" + url.split("/", 3)[-1] if "/" in url[8:] else "/"

        # Default skeleton request
        skeleton = "{} {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(
            method, target_path, target_host
        ).encode("utf-8")

        example_response_bytes = None

        if not reference:
            return skeleton, None

        try:
            u_ref = URL(reference)
            ref_host = u_ref.getHost()
            ref_proto = u_ref.getProtocol()
            ref_port = u_ref.getPort()
            if ref_port == -1:
                ref_port = 443 if ref_proto == "https" else 80
            ref_path = u_ref.getPath() or "/"
            if u_ref.getQuery():
                ref_path += "?" + u_ref.getQuery()

            service = self._extender._helpers.buildHttpService(ref_host, ref_port, ref_proto)
            req_for_ref = "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n".format(ref_path, ref_host).encode("utf-8")
            resp_obj = self._extender._callbacks.makeHttpRequest(service, req_for_ref)
            resp_bytes = resp_obj.getResponse()
            if not resp_bytes:
                raise Exception("empty response from reference")

            analyzed = self._extender._helpers.analyzeResponse(resp_bytes)
            body_bytes = resp_bytes[analyzed.getBodyOffset():]
            body = body_bytes.tostring().decode("utf-8", "ignore")
            body = html_parser.unescape(body)
        except Exception as e:
            print("[AHP] Failed to fetch reference {}: {}".format(reference, e))
            return skeleton, None

        req_section = None
        resp_section = None

        # Exact <h2> markers for request and response information
        m_sections = re.search(
            r'(?is)<h2[^>]*>\s*Request\s+Information\s*</h2>(.*?)<h2[^>]*>\s*Response\s+Information\s*</h2>(.*)',
            body
        )
        if m_sections:
            req_section = m_sections.group(1)
            resp_section = m_sections.group(2)
        else:
            m_alt = re.search(r'(?is)<h[1-6][^>]*>.*?Request.*?</h[1-6]>(.*?)<h[1-6][^>]*>.*?Response.*?</h[1-6]>(.*)', body)
            if m_alt:
                req_section = m_alt.group(1)
                resp_section = m_alt.group(2)

        search_target_for_request = req_section if req_section is not None else body

        raw_http = None
        json_example = None

        # Raw HTTP in <pre>
        for pre in re.findall(r'(?is)<pre[^>]*>(.*?)</pre>', search_target_for_request):
            inner = re.sub(r'<[^>]+>', '', pre).strip()
            inner = html_parser.unescape(inner)
            if "HTTP/1.1" in inner or "HTTP/1.0" in inner:
                raw_http = inner
                break

        # JSON example in <pre> / <code>
        if not raw_http:
            blocks = re.findall(r'(?is)<pre[^>]*>(.*?)</pre>', search_target_for_request) + \
                     re.findall(r'(?is)<code[^>]*>(.*?)</code>', search_target_for_request)
            for block in blocks:
                txt = re.sub(r'<[^>]+>', '', block).strip()
                txt = html_parser.unescape(txt)
                if (txt.startswith("{") or txt.startswith("[")) and txt.count(":") >= 1 and len(txt) > 10:
                    json_example = txt
                    break

        if resp_section:
            resp_blocks = re.findall(r'(?is)<pre[^>]*>(.*?)</pre>', resp_section) + \
                          re.findall(r'(?is)<code[^>]*>(.*?)</code>', resp_section)
            if resp_blocks:
                resp_text = re.sub(r'<[^>]+>', '', resp_blocks[0]).strip()
                resp_text = html_parser.unescape(resp_text)
                if resp_text:
                    if not re.match(r'(?i)^\s*HTTP/\d+\.\d+\s+\d+', resp_text):
                        resp_text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + resp_text
                    example_response_bytes = resp_text.encode("utf-8")
                else:
                    example_response_bytes = b"HTTP/1.1 200 OK\r\n\r\nSample not available."
            else:
                example_response_bytes = b"HTTP/1.1 200 OK\r\n\r\nSample not available."
        else:
            m_resp_any = re.search(r'(?is)(Response Information|Sample Response|Response)(.*?)(?:<h|$)', body)
            if m_resp_any:
                block = m_resp_any.group(2)
                rb = re.findall(r'(?is)<pre[^>]*>(.*?)</pre>', block) + re.findall(r'(?is)<code[^>]*>(.*?)</code>', block)
                if rb:
                    resp_text = re.sub(r'<[^>]+>', '', rb[0]).strip()
                    resp_text = html_parser.unescape(resp_text)
                    if resp_text:
                        if not re.match(r'(?i)^\s*HTTP/\d+\.\d+\s+\d+', resp_text):
                            resp_text = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + resp_text
                        example_response_bytes = resp_text.encode("utf-8")
                    else:
                        example_response_bytes = b"HTTP/1.1 200 OK\r\n\r\nSample not available."
                else:
                    example_response_bytes = b"HTTP/1.1 200 OK\r\n\r\nSample not available."
            else:
                example_response_bytes = b"HTTP/1.1 200 OK\r\n\r\nSample not available."

        if raw_http:
            raw_text = raw_http.replace("\r\n", "\n").replace("\r", "\n")
            lines = raw_text.split("\n")
            try:
                idx_blank = lines.index("")
            except ValueError:
                idx_blank = None

            request_line = lines[0].strip() if lines else "{} {}".format(method, target_path)
            request_line = html_parser.unescape(request_line)
            print("request line {}".format(request_line))
            parts = request_line.split()
            sample_method = parts[0] if len(parts) >= 1 else method
            sample_path = parts[1] if len(parts) >= 2 else target_path
            sample_path = html_parser.unescape(sample_path)
            print("sample path {}".format(sample_path))

            if idx_blank is not None:
                headers = lines[1:idx_blank]
                body_lines = lines[idx_blank+1:]
            else:
                headers = lines[1:]
                body_lines = []

            new_headers = []
            found_host = False
            for h in headers:
                if h.lower().startswith("host:"):
                    new_headers.append("Host: {}".format(target_host))
                    found_host = True
                elif h.strip() != "":
                    new_headers.append(h)
            if not found_host:
                new_headers.insert(0, "Host: {}".format(target_host))

            assembled = "{} {} HTTP/1.1\r\n{}\r\n\r\n{}".format(
                sample_method,
                sample_path,
                "\r\n".join(new_headers),
                "\r\n".join(body_lines)
            ).encode("utf-8")
            return assembled, example_response_bytes

        if json_example:
            body_text = json_example.strip()
            content_len = len(body_text.encode("utf-8"))
            content_header = "Content-Type: application/json"
            assembled = "{} {} HTTP/1.1\r\nHost: {}\r\n{}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}".format(
                method, target_path, target_host, content_header, content_len, body_text
            ).encode("utf-8")
            return assembled, example_response_bytes

        return skeleton, example_response_bytes

