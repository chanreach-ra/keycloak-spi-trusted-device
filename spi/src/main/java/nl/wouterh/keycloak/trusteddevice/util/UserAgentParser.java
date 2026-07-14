package nl.wouterh.keycloak.trusteddevice.util;

import jakarta.ws.rs.core.HttpHeaders;
import org.keycloak.models.KeycloakSession;
import ua_parser.Client;
import ua_parser.Parser;

public class UserAgentParser {

  // Eager initialization avoids double-checked locking without volatile
  private static final Parser PARSER = new Parser();

  public static String getDeviceName(KeycloakSession session) {
    String userAgent = session.getContext().getRequestHeaders()
        .getHeaderString(HttpHeaders.USER_AGENT);

    if (userAgent == null) {
      return null;
    }

    if (userAgent.length() > 512) {
      return null;
    }

    Client parsed = PARSER.parse(userAgent);
    String rawName = parsed.userAgent.family + " on " + parsed.os.family;

    // Strip HTML-special and non-printable characters before the name is
    // rendered in a FreeMarker template (M-3 / stored-XSS hardening).
    return rawName.replaceAll("[^\\w\\s.\\-]", "").strip();
  }

}
