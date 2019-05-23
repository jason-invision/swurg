/*
#    Copyright (C) 2016 Alexandre Teyar

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
#    limitations under the License. 
*/

package swurg.utils;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.fasterxml.jackson.databind.module.SimpleModule;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IParameter;
import io.swagger.oas.inflector.examples.ExampleBuilder;
import io.swagger.oas.inflector.examples.XmlExampleSerializer;
import io.swagger.oas.inflector.examples.models.Example;
import io.swagger.oas.inflector.processors.JsonNodeExampleSerializer;
import io.swagger.util.Json;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.PathItem.HttpMethod;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;

public class ExtensionHelper {

  private IExtensionHelpers burpExtensionHelpers;
  private IBurpExtenderCallbacks callbacks;
  private PrintWriter stdout;

  public ExtensionHelper(IBurpExtenderCallbacks callbacks) {
    this.burpExtensionHelpers = callbacks.getHelpers();
    this.callbacks = callbacks;
    this.stdout = new PrintWriter(callbacks.getStdout(), true);
  }

  public IExtensionHelpers getBurpExtensionHelpers() {
    return this.burpExtensionHelpers;
  }

  private List<String> buildHeaders(URL url, Map.Entry<String, PathItem> path,
      Map.Entry<HttpMethod, Operation> operation, String contentType) {
    List<String> headers = new ArrayList<>();

    headers.add(operation.getKey().toString() + " " + url.getPath() + path.getKey() + " HTTP/1.1");
    headers.add("Host: " + url.getHost());
    headers.add("Content-Type: " + contentType);

    LinkedHashMap<String, ApiResponse> responses = operation.getValue().getResponses();
    if(responses != null) {
      StringBuilder sb = new StringBuilder("Accept: ");
      for (ApiResponse response : responses.values()) {
        Content content = response.getContent();
        if (content != null) {
          sb.append(String.join(",", content.keySet()));
          //headers.add("Accept: " + String.join(",", content.keySet()));
        }
      }
      if(sb.length() > 9) {
        headers.add(sb.toString());
      }
    }

    return headers;
  }

  public byte[] buildRequest(
      URL url, Map.Entry<String, PathItem> path, Map.Entry<HttpMethod, Operation>  operation, String contentType, Example example
  ) {
    List<String> headers = buildHeaders(url, path, operation, contentType);
    String body = new String();

    if(contentType.equals("application/json")) {
      SimpleModule simpleModule = new SimpleModule().addSerializer(new JsonNodeExampleSerializer());
      Json.mapper().registerModule(simpleModule);
      body = Json.pretty(example);
    } else if(contentType.equals("application/xml")) {
      body = new XmlExampleSerializer().serialize(example);
    }

    byte[] httpMessage = this.burpExtensionHelpers.buildHttpMessage(headers, body.getBytes());

    List<Parameter> parameters = operation.getValue().getParameters();
    if (parameters != null) {
      for (Parameter parameter : parameters) {

        String in = parameter.getIn();
        if (in != null) {
          Schema schema = parameter.getSchema();
          if (schema != null) {
            switch (in) {
              case "body":
                httpMessage = this.burpExtensionHelpers
                    .addParameter(httpMessage, this.burpExtensionHelpers
                        .buildParameter(parameter.getName(), parameter.getSchema().getType(), IParameter.PARAM_BODY));
              case "query":
                httpMessage = this.burpExtensionHelpers
                    .addParameter(httpMessage, this.burpExtensionHelpers
                    .buildParameter(parameter.getName(), parameter.getSchema().getType(), IParameter.PARAM_URL));
                  }
            }
          }
  
        }
    }

    return httpMessage;
  }

}
