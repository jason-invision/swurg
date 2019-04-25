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

package swurg.process;

import com.google.common.base.Strings;
import io.swagger.models.Swagger;
import io.swagger.parser.SwaggerParser;
import io.swagger.parser.util.SwaggerDeserializationResult;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.converter.SwaggerConverter;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.MapUtils;

public class Loader {

  public OpenAPI process(String resource) {
    if (Strings.isNullOrEmpty(resource)) {
      throw new IllegalArgumentException("No file or URL specified");
    }

    if (new File(resource).exists()) {
      assert true;
    } else {
      try {
        new URL(resource).toURI();
      } catch (MalformedURLException | URISyntaxException e) {
        throw new IllegalArgumentException(
            String.format("%s does not exist or is an invalid URL", resource));
      }
    }

    Swagger swagger = new SwaggerParser().read(resource);

    if (swagger == null) {
      OpenAPI openAPI = new OpenAPIV3Parser().read(resource);
      
      if (openAPI == null) {
        throw new NullPointerException(
          String.format(
              "The OpenAPI specification contained in %s is ill formed and cannot be parsed",
              resource));
      } else {
        return openAPI;
      }

    } else {      
      validateSpecification(swagger, resource);

      SwaggerConverter converter = new SwaggerConverter();
      ParseOptions parseOptions = new ParseOptions();
      parseOptions.setResolve(false);
      SwaggerDeserializationResult dResult = new SwaggerDeserializationResult();
      dResult.setSwagger(swagger);
      SwaggerParseResult pResult = converter.convert(dResult);
      return pResult.getOpenAPI();
    }
  }

  private void validateSpecification(Swagger swagger, String resource) {
    if (Strings.isNullOrEmpty(swagger.getHost())) {
      throw new IllegalArgumentException(
          String.format(
              "The OpenAPI specification contained in %s is missing the mandatory field: 'host'",
              resource));
    }

    if (CollectionUtils.isEmpty(swagger.getSchemes())) {
      throw new IllegalArgumentException(
          String.format(
              "The OpenAPI specification contained in %s is missing the mandatory field: 'schemes'",
              resource));
    }

    if (MapUtils.isEmpty(swagger.getPaths())) {
      throw new IllegalArgumentException(
          String.format(
              "The OpenAPI specification contained in %s is missing the mandatory field: 'paths'",
              resource));
    }
  }
}
