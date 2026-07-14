package nl.wouterh.keycloak.trusteddevice.authenticator;

import static nl.wouterh.keycloak.trusteddevice.authenticator.RegisterTrustedDeviceAuthenticatorFactory.CONF_DURATION;

import com.google.common.base.Strings;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialModel;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProvider;
import nl.wouterh.keycloak.trusteddevice.credential.TrustedDeviceCredentialProviderFactory;
import nl.wouterh.keycloak.trusteddevice.util.TrustedDeviceToken;
import nl.wouterh.keycloak.trusteddevice.util.UserAgentParser;
import org.apache.commons.codec.binary.Hex;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class RegisterTrustedDeviceAuthenticator implements Authenticator {

  private static final SecureRandom secureRandom = new SecureRandom();
  private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd")
      .withZone(ZoneId.of("UTC"));

  /** Maximum length (characters) for a user-supplied device name. */
  private static final int MAX_DEVICE_NAME_LENGTH = 64;

  /** Maximum number of trusted devices a single user may register. */
  private static final int MAX_TRUSTED_DEVICES = 10;

  /**
   * Upper bound on trust duration (2 years in seconds).
   * Prevents admins from accidentally setting an unreasonably long TTL.
   */
  private static final long MAX_DURATION_SECONDS = Duration.ofDays(365 * 2).getSeconds();

  /** Maximum iterations when making a credential label unique (prevents infinite loops). */
  private static final int MAX_DEDUP_ITERATIONS = 50;

  private final KeycloakSession session;

  public RegisterTrustedDeviceAuthenticator(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public void authenticate(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    TrustedDeviceCredentialModel credential = TrustedDeviceToken.getCredentialFromCookie(
        context.getSession(), realm, user);

    if (credential != null) {
      context.success();
    } else {
      Response form = context.form()
          .setAttribute("trustedDeviceName", UserAgentParser.getDeviceName(session))
          .createForm("trusted-device-register.ftl");
      context.challenge(form);
    }
  }

  @Override
  public void action(AuthenticationFlowContext context) {
    UserModel user = context.getUser();
    RealmModel realm = context.getRealm();

    TrustedDeviceCredentialModel existingCredential = TrustedDeviceToken.getCredentialFromCookie(
        session, context.getRealm(), context.getUser());
    if (existingCredential != null) {
      // H-2: always advance the flow, never leave it in an undefined state
      context.success();
      return;
    }

    Duration duration = null;

    AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
    if (authenticatorConfig != null) {
      Map<String, String> config = authenticatorConfig.getConfig();
      if (config != null && !Strings.isNullOrEmpty(config.get(CONF_DURATION))) {
        duration = Duration.parse(config.get(CONF_DURATION));
        // H-3: cap trust duration to MAX_DURATION_SECONDS (2 years)
        if (duration.getSeconds() > MAX_DURATION_SECONDS) {
          duration = Duration.ofSeconds(MAX_DURATION_SECONDS);
        }
      }
    }

    MultivaluedMap<String, String> formParameters = context.getHttpRequest()
        .getDecodedFormParameters();

    boolean trustedDevice = "yes".equals(formParameters.getFirst("trusted-device"));

    // H-1: sanitize device name — cap length and strip HTML-special characters
    String rawDeviceName = formParameters.getFirst("trusted-device-name");
    String deviceName = sanitizeDeviceName(rawDeviceName);

    if (trustedDevice && !Strings.isNullOrEmpty(deviceName)) {
      TrustedDeviceCredentialProvider trustedDeviceCredentialProvider =
          (TrustedDeviceCredentialProvider) session.getProvider(
              CredentialProvider.class, TrustedDeviceCredentialProviderFactory.PROVIDER_ID);

      // Remove expired credentials first, then re-check the live count
      trustedDeviceCredentialProvider.removeExpiredCredentials(realm, user);

      // M-2: enforce max trusted devices; evict the oldest one if the cap is reached
      long activeDeviceCount = user.credentialManager()
          .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
          .count();
      if (activeDeviceCount >= MAX_TRUSTED_DEVICES) {
        user.credentialManager()
            .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
            .min((a, b) -> {
              Long aDate = a.getCreatedDate();
              Long bDate = b.getCreatedDate();
              if (aDate == null) return -1;
              if (bDate == null) return 1;
              return Long.compare(aDate, bDate);
            })
            .ifPresent(oldest ->
                trustedDeviceCredentialProvider.deleteCredential(realm, user, oldest.getId()));
      }

      // Generate a random 32-byte deviceId
      byte[] bytes = new byte[32];
      secureRandom.nextBytes(bytes);
      String deviceId = Hex.encodeHexString(bytes);

      // Compute expiry (epoch seconds)
      Long exp = null;
      String credentialName = deviceName;
      if (duration != null) {
        exp = Time.currentTime() + duration.getSeconds(); // epoch seconds

        credentialName = String.format("%s (Expires: %s)", deviceName,
            formatter.format(Instant.ofEpochSecond(exp)));
      }

      Set<String> existingLabels = user.credentialManager()
          .getStoredCredentialsByTypeStream(TrustedDeviceCredentialModel.TYPE_TWOFACTOR)
          .map(CredentialModel::getUserLabel)
          .collect(Collectors.toSet());

      {
        // L-2: suffix credentialName to make it unique, bounded to MAX_DEDUP_ITERATIONS
        int suffix = 2;
        final String base = credentialName;
        while (existingLabels.contains(credentialName) && suffix <= MAX_DEDUP_ITERATIONS + 1) {
          credentialName = base + " " + suffix;
          suffix++;
        }
      }

      TrustedDeviceCredentialModel trustedDeviceCredentialModel =
          TrustedDeviceCredentialModel.create(credentialName, deviceId, exp);

      // Add the new credential
      CredentialModel credential = trustedDeviceCredentialProvider.createCredential(realm, user,
          trustedDeviceCredentialModel);

      int cookieExpirationTime =
          duration != null ? (int) duration.getSeconds() : Integer.MAX_VALUE;

      TrustedDeviceToken token = new TrustedDeviceToken(credential.getId(), deviceId, exp);
      TrustedDeviceToken.addCookie(session, realm, token, cookieExpirationTime);
    }

    context.success();
  }

  /**
   * Sanitizes a user-supplied device name.
   * <ul>
   *   <li>Returns {@code null} when the input is null or blank.</li>
   *   <li>Strips characters that are not word characters, spaces, dots, or hyphens
   *       to prevent stored-XSS through FreeMarker templates.</li>
   *   <li>Truncates to {@link #MAX_DEVICE_NAME_LENGTH} characters.</li>
   * </ul>
   */
  private static String sanitizeDeviceName(String raw) {
    if (Strings.isNullOrEmpty(raw)) {
      return null;
    }
    String sanitized = raw.replaceAll("[^\\w\\s.\\-]", "").strip();
    if (sanitized.length() > MAX_DEVICE_NAME_LENGTH) {
      sanitized = sanitized.substring(0, MAX_DEVICE_NAME_LENGTH).strip();
    }
    return sanitized.isEmpty() ? null : sanitized;
  }

  @Override
  public boolean requiresUser() {
    return true;
  }

  @Override
  public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    return true;
  }

  @Override
  public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
  }

  @Override
  public void close() {

  }
}
