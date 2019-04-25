package burp;

import static burp.BurpExtender.COPYRIGHT;
import static burp.BurpExtender.EXTENSION;

import io.swagger.models.Swagger;
import io.swagger.v3.oas.models.OpenAPI;

import java.awt.Color;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import swurg.process.Loader;
import swurg.ui.Tab;

public class ContextMenuFactory implements IContextMenuFactory {

  private IBurpExtenderCallbacks callbacks;
  private Tab tab;

  ContextMenuFactory(IBurpExtenderCallbacks callbacks, Tab tab) {
    this.callbacks = callbacks;
    this.tab = tab;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    List<JMenuItem> jMenuItems = new ArrayList<>();
    JMenuItem send_to_swagger_parser = new JMenuItem(String.format("Send to %s", EXTENSION));
    send_to_swagger_parser.addActionListener(e -> {
      for (IHttpRequestResponse selectedMessage : invocation.getSelectedMessages()) {
        IRequestInfo requestInfo = this.callbacks.getHelpers().analyzeRequest(selectedMessage);
        String resource = requestInfo.getUrl().toString();

        try {
          OpenAPI openAPI = new Loader().process(resource);
          this.tab.populateTable(openAPI);
          this.tab.printStatus(COPYRIGHT, Color.BLACK);
        } catch (IllegalArgumentException | NullPointerException e1) {
          this.tab.printStatus("Exception: " + e1.getMessage(), Color.RED);
        } catch (MalformedURLException e1) {
          this.tab.printStatus("Exception: " + e1.getMessage(), Color.RED);
        } catch (Exception e1) {
          this.tab.printStatus("Exception: " + e1.getMessage(), Color.RED);
        }
      }
    });

    jMenuItems.add(send_to_swagger_parser);

    return jMenuItems;
  }
}
