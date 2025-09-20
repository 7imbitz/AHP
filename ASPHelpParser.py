import threading
import re
from xml.sax.saxutils import unescape

from burp import IBurpExtender, ITab, IContextMenuFactory
from javax.swing import (
    JPanel, BoxLayout, JMenuItem,
    SwingUtilities, JSplitPane, JTextArea, JScrollPane
)
from java.util import ArrayList


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("ASPHelpParser")

        # --- UI Layout ---
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        # Plain text output area
        self._outputArea = JTextArea()
        self._outputArea.setEditable(False)
        scroll = JScrollPane(self._outputArea)

        # Single pane layout (plain text)
        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split.setLeftComponent(scroll)
        split.setRightComponent(None)
        split.setDividerLocation(800)

        self.panel.add(split)

        # Register tab + context menu
        self._callbacks.addSuiteTab(self)
        self._callbacks.registerContextMenuFactory(self)

        print("[AHP] Extension loaded successfully.")

    # ----- ITab -----
    def getTabCaption(self):
        return "AHP"

    def getUiComponent(self):
        return self.panel

    # ----- Context menu -----
    def createMenuItems(self, invocation):
        items = ArrayList()
        selected = invocation.getSelectedMessages()
        if not selected:
            return items

        menu_item = JMenuItem("Send to AHP")

        def on_menu(event, msgs=selected):
            try:
                msg = msgs[0]
                resp = msg.getResponse()
                if not resp:
                    self._outputArea.setText("[AHP] No response found")
                    return

                analyzed = self._helpers.analyzeResponse(resp)
                body_offset = analyzed.getBodyOffset()
                body_bytes = resp[body_offset:]
                # use helper to convert bytes to string safely
                try:
                    body_str = self._helpers.bytesToString(body_bytes)
                except Exception:
                    # fallback: try to call tostring (older objects)
                    try:
                        body_str = body_bytes.tostring()
                    except Exception:
                        body_str = str(body_bytes)

                # Unescape common HTML entities to make link text nicer
                body_str = unescape(body_str)

                # Extract <a href="...">text</a>
                anchors = re.findall(r'<a\b[^>]*href=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</a>',
                                     body_str, re.IGNORECASE | re.DOTALL)

                if not anchors:
                    self._outputArea.setText("[AHP] No endpoints found in /Help response")
                    return

                host = msg.getHttpService().getHost()
                port = msg.getHttpService().getPort()
                proto = "https" if msg.getHttpService().getProtocol() == "https" else "http"

                lines = ["#\tMethod\tURL"]
                count = 1
                for href, text in anchors:
                    # Normalize whitespace in link text
                    text_clean = re.sub(r'\s+', ' ', text).strip()

                    # Only handle links whose text starts with an HTTP verb (GET/POST/PUT/DELETE/PATCH)
                    m = re.match(r'^(GET|POST|PUT|DELETE|PATCH|OPTIONS)\s+(.+)$', text_clean, re.IGNORECASE)
                    if not m:
                        # skip non-api links like "Home" / "API"
                        continue

                    method = m.group(1).upper()
                    path_part = m.group(2).strip()

                    # If href is an absolute URL, use it directly
                    if href.startswith("http://") or href.startswith("https://"):
                        full_url = href
                    else:
                        # ensure leading slash
                        if not href.startswith("/"):
                            href = "/" + href
                        # remove any duplicate slashes when joining
                        full_url = "{proto}://{host}:{port}{href}".format(
                            proto=proto, host=host, port=port, href=href
                        )

                    # Some link text contains the full api path already (like "GET api/Services/...")
                    # Use that path_part to create a cleaner URL if possible
                    # If path_part already contains "http" or starts with "/", prefer href.
                    if path_part.lower().startswith("http") or path_part.startswith("/"):
                        display_url = full_url
                    else:
                        # path_part might be like: api/Services/GetTaxByMyKadNo?mykadno={mykadno}
                        # ensure a leading slash
                        if not path_part.startswith("/"):
                            path_part2 = "/" + path_part
                        else:
                            path_part2 = path_part
                        display_url = "{proto}://{host}:{port}{path}".format(
                            proto=proto, host=host, port=port, path=path_part2
                        )

                    lines.append("{idx}\t{method}\t{url}".format(idx=count, method=method, url=display_url))
                    count += 1

                self._outputArea.setText("\n".join(lines))

                # bring AHP tab to front
                SwingUtilities.invokeLater(self._select_our_tab)

            except Exception as e:
                print("[AHP] Error parsing menu action:", e)

        menu_item.addActionListener(on_menu)
        items.add(menu_item)
        return items

    # ----- select tab helper -----
    def _select_our_tab(self):
        try:
            root = SwingUtilities.getRoot(self.panel)
            if not root:
                return

            def find_tabbed(comp):
                try:
                    cls_name = comp.getClass().getName()
                    if "JTabbedPane" in cls_name:
                        for i in range(comp.getTabCount()):
                            if comp.getTitleAt(i) == self.getTabCaption():
                                comp.setSelectedIndex(i)
                                return True
                    for child in comp.getComponents():
                        if find_tabbed(child):
                            return True
                except Exception:
                    pass
                return False

            find_tabbed(root)
        except Exception:
            pass
