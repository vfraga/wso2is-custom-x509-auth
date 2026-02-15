package org.wso2.support.sample.x509authenticator;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.ssl.asn1.ASN1InputStream;
import org.apache.commons.ssl.asn1.DEREncodable;
import org.apache.commons.ssl.asn1.DERSequence;
import org.apache.commons.ssl.asn1.DERTaggedObject;
import org.apache.commons.ssl.asn1.DERUTF8String;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.util.UserCoreUtil;

/** X509 Certificate-based authenticator for WSO2 Identity Server. */
public class X509CertificateAuthenticator extends AbstractApplicationAuthenticator
    implements LocalApplicationAuthenticator {

  private static final Log log = LogFactory.getLog(X509CertificateAuthenticator.class);
  private static final String AUTH_FAILURE_PARAM = "authFailure";
  private static final String ERROR_CODE_PARAM = "errorCode";

  private volatile Pattern alternativeNamesPatternCompiled;
  private volatile Pattern subjectPatternCompiled;

  public X509CertificateAuthenticator() {}

  @Override
  protected void initiateAuthenticationRequest(
      final HttpServletRequest httpServletRequest,
      final HttpServletResponse httpServletResponse,
      final AuthenticationContext authenticationContext)
      throws AuthenticationFailedException {

    try {
      if (authenticationContext.isRetrying()) {
        redirectToErrorPage(httpServletResponse, authenticationContext);
      } else {
        redirectToAuthEndpoint(httpServletResponse, authenticationContext);
      }
    } catch (final IOException e) {
      throw new AuthenticationFailedException("Exception while redirecting to the login page", e);
    }
  }

  @Override
  protected void processAuthenticationResponse(
      final HttpServletRequest httpServletRequest,
      final HttpServletResponse httpServletResponse,
      final AuthenticationContext authenticationContext)
      throws AuthenticationFailedException {

    final X509Certificate cert = extractCertificate(httpServletRequest, authenticationContext);
    final String certAttributes = cert.getSubjectX500Principal().toString();
    final Map<ClaimMapping, String> claims =
        getSubjectAttributes(authenticationContext, certAttributes);

    final String alternativeNamePattern = getAlternativeNamePattern();
    if (alternativeNamePattern != null) {
      final String alternativeName = getMatchedAlternativeName(cert, authenticationContext);

      if (log.isDebugEnabled()) {
        log.debug("Validating certificate using the alternative name: " + alternativeNamePattern);
      }

      validateAndSetUsername(alternativeName, authenticationContext, cert, claims);
    } else {
      final String subjectAttributePattern = getSubjectAttributePattern();
      if (subjectAttributePattern != null) {
        final String subjectAttribute =
            getMatchedSubjectAttribute(certAttributes, authenticationContext);
        if (log.isDebugEnabled()) {
          log.debug(
              "Validating certificate using the certificate subject attribute: "
                  + subjectAttributePattern);
        }

        validateAndSetUsername(subjectAttribute, authenticationContext, cert, claims);
      } else {
        handleFallbackUsername(authenticationContext, cert, claims);
      }
    }
  }

  @Override
  public boolean canHandle(final HttpServletRequest httpServletRequest) {
    return httpServletRequest.getParameter(X509CertificateConstants.SUCCESS) != null;
  }

  @Override
  public String getContextIdentifier(final HttpServletRequest httpServletRequest) {
    return httpServletRequest.getParameter(X509CertificateConstants.SESSION_DATA_KEY);
  }

  @Override
  public String getName() {
    return X509CertificateConstants.AUTHENTICATOR_NAME;
  }

  @Override
  public String getFriendlyName() {
    return X509CertificateConstants.AUTHENTICATOR_FRIENDLY_NAME;
  }

  @Override
  protected boolean retryAuthenticationEnabled() {
    return true;
  }

  /** Redirects to the error page with failure details. */
  private void redirectToErrorPage(
      final HttpServletResponse response, final AuthenticationContext ctx) throws IOException {

    final String errorPageUrl =
        IdentityUtil.getServerURL(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_JSP_PATH, false, false);

    final Map<String, String> queryParams = new HashMap<>();
    queryParams.put(X509CertificateConstants.SESSION_DATA_KEY, ctx.getContextIdentifier());
    queryParams.put(X509CertificateConstants.AUTHENTICATORS, getName());
    queryParams.put(AUTH_FAILURE_PARAM, "true");
    queryParams.put(
        ERROR_CODE_PARAM,
        (String)
            ctx.getProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY));

    final String redirectUrl =
        X509CertificateUtil.buildRedirectURL(errorPageUrl, queryParams, ctx.getQueryParams());

    ctx.setProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY, "");

    if (log.isDebugEnabled()) {
      log.debug("Redirect to error page: " + redirectUrl);
    }
    response.sendRedirect(redirectUrl);
  }

  /** Redirects to authentication endpoint with session context. */
  private void redirectToAuthEndpoint(
      final HttpServletResponse response, final AuthenticationContext ctx) throws IOException {

    String authEndpoint =
        getAuthenticatorConfig()
            .getParameterMap()
            .get(X509CertificateConstants.AUTHENTICATION_ENDPOINT_CONFIG_PROPERTY);
    if (StringUtils.isEmpty(authEndpoint)) {
      authEndpoint = X509CertificateConstants.X509_CERTIFICATE_SERVLET_URL;
    }

    final Map<String, String> queryParams = new HashMap<>();
    queryParams.put(X509CertificateConstants.SESSION_DATA_KEY, ctx.getContextIdentifier());

    if (ctx.getCallerSessionKey() != null) {
      queryParams.put("callerSessionKey", ctx.getCallerSessionKey());
    }

    final String redirectUrl =
        X509CertificateUtil.buildRedirectURL(authEndpoint, queryParams, ctx.getQueryParams());

    if (log.isDebugEnabled()) {
      log.debug("Request sent to " + authEndpoint);
    }

    response.sendRedirect(redirectUrl);
  }

  /** Extracts and validates the {@link X509Certificate} from the request / context. */
  private X509Certificate extractCertificate(
      final HttpServletRequest request, final AuthenticationContext ctx)
      throws AuthenticationFailedException {

    Object object = ctx.getProperty(X509CertificateConstants.X_509_CERTIFICATE);
    if (object == null) {
      object = request.getAttribute(X509CertificateConstants.X_509_CERTIFICATE);
    }
    if (object == null) {
      if (log.isDebugEnabled()) {
        log.debug("X509 certificate not found in the request or context.");
      }
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.X509_CERTIFICATE_NOT_FOUND_ERROR_CODE);
      throw new AuthenticationFailedException("Unable to find X509 Certificate in browser");
    }
    if (!(object instanceof X509Certificate[])) {
      throw new AuthenticationFailedException("Exception while casting the X509Certificate");
    }

    final X509Certificate[] certificates = (X509Certificate[]) object;
    if (certificates.length == 0) {
      throw new AuthenticationFailedException("X509Certificate object is null");
    }

    if (log.isDebugEnabled()) {
      log.debug("X509 Certificate Checking in servlet is done!");
    }
    return certificates[0];
  }

  private void validateAndSetUsername(
      final String subject,
      final AuthenticationContext ctx,
      final X509Certificate cert,
      final Map<ClaimMapping, String> claims)
      throws AuthenticationFailedException {

    validateUsingSubject(subject, ctx, cert, claims);
    ctx.setProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME_CONTEXT_PROPERTY, subject);
  }

  private void handleFallbackUsername(
      final AuthenticationContext ctx,
      final X509Certificate cert,
      final Map<ClaimMapping, String> claims)
      throws AuthenticationFailedException {

    final String userName =
        (String)
            ctx.getProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME_CONTEXT_PROPERTY);
    if (StringUtils.isEmpty(userName)) {
      if (log.isDebugEnabled()) {
        log.debug("Username not found for X509Certificate's attribute.");
      }

      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.USERNAME_NOT_FOUND_ON_X509_CERTIFICATE_ATTRIBUTE);
      throw new AuthenticationFailedException(
          "Couldn't find the username for X509Certificate's attribute");
    }
    validateUsingSubject(userName, ctx, cert, claims);
    if (log.isDebugEnabled()) {
      // Do not log the username value to avoid exposing user data.
      log.debug("Certificate validated using the certificate username attribute.");
    }
  }

  /**
   * Finds the single string that matches {@code UsernameRegex} from the certificate's subject DN.
   */
  private String getMatchedSubjectAttribute(
      final String certAttributes, final AuthenticationContext ctx)
      throws AuthenticationFailedException {

    final LdapName ldapDN = parseLdapName(certAttributes);
    final String userNameAttribute =
        getAuthenticatorConfig().getParameterMap().get(X509CertificateConstants.USERNAME);
    final Set<String> matches = new HashSet<>();

    final Pattern pattern = getSubjectPattern();
    for (final Rdn rdn : ldapDN.getRdns()) {
      // Extracts matching username from certificate attributes
      if (pattern != null && userNameAttribute.equals(rdn.getType())) {
        final Matcher m = pattern.matcher(String.valueOf(rdn.getValue()));
        addMatchStringsToList(m, matches);
      }
    }

    return resolveSingleMatch(matches, ctx, userNameAttribute);
  }

  /** Finds the single alternative name that matches {@code AlternativeNamesRegex}. */
  private String getMatchedAlternativeName(
      final X509Certificate cert, final AuthenticationContext ctx)
      throws AuthenticationFailedException {

    final Set<String> matches = new HashSet<>();
    try {
      final Collection<List<?>> altNames = cert.getSubjectAlternativeNames();
      if (altNames == null) {
        if (log.isDebugEnabled()) {
          log.debug("Subject Alternative Names not found in the certificate.");
        }
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.X509_CERTIFICATE_ALT_NAME_NOT_FOUND_ERROR_CODE);
        throw new AuthenticationFailedException(
            X509CertificateConstants.X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR);
      }

      final Pattern pattern = getAlternativeNamesPattern();
      for (final List<?> item : altNames) {
        final Object value = item.get(1);
        if (value instanceof byte[]) {
          // Decodes ASN1 input stream to extract identity
          try (final ASN1InputStream decoder = new ASN1InputStream((byte[]) value)) {
            final String identity = decodeAlternativeName(decoder);
            if (identity != null && pattern != null) {
              final Matcher m = pattern.matcher(identity);
              addMatchStringsToList(m, matches);
            }
          }
        } else if (value instanceof String && pattern != null) {
          final Matcher m = pattern.matcher((String) value);
          addMatchStringsToList(m, matches);
        }
      }
    } catch (final CertificateParsingException | IOException e) {
      throw new AuthenticationFailedException("Failed to parse the certificate", e);
    }

    return resolveSingleAlternativeNameMatch(matches, ctx);
  }

  /** Ensures exactly one match exists; sets the appropriate error code and throws otherwise. */
  private String resolveSingleMatch(
      final Set<String> matches, final AuthenticationContext ctx, final String userNameAttribute)
      throws AuthenticationFailedException {

    if (matches.isEmpty()) {
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.X509_CERTIFICATE_SUBJECT_DN_REGEX_NO_MATCHES_ERROR_CODE);
      if (log.isDebugEnabled()) {
        log.debug(X509CertificateConstants.X509_CERTIFICATE_SUBJECT_DN_REGEX_NO_MATCHES_ERROR);
      }
      throw new AuthenticationFailedException(
          X509CertificateConstants.X509_CERTIFICATE_SUBJECT_DN_REGEX_NO_MATCHES_ERROR);
    }
    if (matches.size() > 1) {
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.X509_CERTIFICATE_SUBJECT_DN_MULTIPLE_MATCHES_ERROR_CODE);
      if (log.isDebugEnabled()) {
        log.debug(
            "More than one value matched with the given regex, matches: "
                + Arrays.toString(matches.toArray()));
      }
      throw new AuthenticationFailedException("More than one value matched with the given regex");
    }

    final String matched = matches.iterator().next();
    if (log.isDebugEnabled()) {
      // Intentionally not logging the matched attribute value.
      log.debug("Setting X509Certificate username attribute: " + userNameAttribute + ".");
    }
    ctx.setProperty(X509CertificateConstants.X509_CERTIFICATE_USERNAME_CONTEXT_PROPERTY, matched);
    return matched;
  }

  private String resolveSingleAlternativeNameMatch(
      final Set<String> matches, final AuthenticationContext ctx)
      throws AuthenticationFailedException {

    if (matches.isEmpty()) {
      if (log.isDebugEnabled()) {
        log.debug("Regex configured for Alternative Names but no matches found.");
      }
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.X509_CERTIFICATE_ALT_NAME_NO_MATCHES_ERROR_CODE);
      throw new AuthenticationFailedException(
          "Regex Configured but no matches found for the given regex");
    }
    if (matches.size() > 1) {
      if (log.isDebugEnabled()) {
        log.debug("More than one match found for Alternative Names with the configured regex.");
      }
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.X509_CERTIFICATE_ALT_NAME_MULTIPLE_MATCHES_ERROR_CODE);
      throw new AuthenticationFailedException("More than one match for the given regex");
    }
    return matches.iterator().next();
  }

  /**
   * Decodes the certificate's Alternative Name from its ASN.1 encoded form. Navigates the nested
   * DER structure to extract the UTF-8 string identity.
   */
  private String decodeAlternativeName(final ASN1InputStream decoder) throws IOException {
    final DEREncodable encoded = decoder.readObject();
    if (encoded instanceof DERSequence) {
      final DERSequence sequence = (DERSequence) encoded;
      // Extracts UTF‑8 string from the nested ASN.1 structure
      if (sequence.size() > 1) {
        DEREncodable sequenceItem = sequence.getObjectAt(1);
        if (sequenceItem instanceof DERTaggedObject) {
          DEREncodable taggedObject = ((DERTaggedObject) sequenceItem).getObject();
          if (taggedObject instanceof DERTaggedObject) {
            DEREncodable innerTaggedObject = ((DERTaggedObject) taggedObject).getObject();
            if (innerTaggedObject instanceof DERUTF8String) {
              return ((DERUTF8String) innerTaggedObject).getString();
            }
          }
        }
      }
    }
    return null;
  }

  private String getAlternativeNamePattern() {
    final String patternString =
        getAuthenticatorConfig()
            .getParameterMap()
            .get(X509CertificateConstants.ALTERNATIVE_NAMES_REGEX_CONFIG_PROPERTY);
    if (patternString != null) {
      if (alternativeNamesPatternCompiled == null
          || !patternString.equals(alternativeNamesPatternCompiled.pattern())) {
        alternativeNamesPatternCompiled = Pattern.compile(patternString);
      }
    } else {
      alternativeNamesPatternCompiled = null;
    }
    return patternString;
  }

  private Pattern getAlternativeNamesPattern() {
    getAlternativeNamePattern();
    return alternativeNamesPatternCompiled;
  }

  private String getSubjectAttributePattern() {
    final String patternString =
        getAuthenticatorConfig()
            .getParameterMap()
            .get(X509CertificateConstants.USER_NAME_REGEX_CONFIG_PROPERTY);
    if (patternString != null) {
      if (subjectPatternCompiled == null
          || !patternString.equals(subjectPatternCompiled.pattern())) {
        subjectPatternCompiled = Pattern.compile(patternString);
      }
    } else {
      subjectPatternCompiled = null;
    }
    return patternString;
  }

  private Pattern getSubjectPattern() {
    getSubjectAttributePattern();
    return subjectPatternCompiled;
  }

  /** Validates the certificate against the resolved user. */
  private void validateUsingSubject(
      final String subject,
      final AuthenticationContext ctx,
      final X509Certificate cert,
      final Map<ClaimMapping, String> claims)
      throws AuthenticationFailedException {

    final byte[] data = encodeCertificate(cert);
    final String tenantDomain =
        StringUtils.isNotBlank(ctx.getTenantDomain())
            ? ctx.getTenantDomain()
            : X509CertificateConstants.SUPER_TENANT_DOMAIN_NAME;
    final String username = X509CertificateUtil.getResolvedUsername(subject, tenantDomain, ctx);
    final String identifier = username != null ? username : subject;
    final AuthenticatedUser authenticatedUser = getAuthenticatedUserFromSteps(ctx);

    if (authenticatedUser == null) {
      addOrValidateCertificate(identifier, tenantDomain, ctx, data, claims, cert);
      return;
    }

    if (log.isDebugEnabled()) {
      // Avoid logging potentially sensitive username data.
      log.debug("Authenticated user found from previous steps.");
    }
    final AuthenticatedUser tempUser = createAuthenticatedUser(identifier, tenantDomain);

    if (!authenticatedUser.equals(tempUser)) {
      if (log.isDebugEnabled()) {
        log.debug(
            "User conflict: the certificate does not belong to the currently authenticated user.");
      }
      ctx.setProperty(
          X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
          X509CertificateConstants.USERNAME_CONFLICT);
      throw new AuthenticationFailedException(
          "The certificate does not belong to the currently authenticated user.");
    }

    addOrValidateCertificate(identifier, tenantDomain, ctx, data, claims, cert);
  }

  private byte[] encodeCertificate(final X509Certificate cert)
      throws AuthenticationFailedException {
    try {
      return cert.getEncoded();
    } catch (final CertificateEncodingException e) {
      throw new AuthenticationFailedException(
          "Error while encoding the certificate with serial number: " + cert.getSerialNumber(), e);
    }
  }

  /** Validates or enrolls the certificate and, on success, authorizes the user. */
  private void addOrValidateCertificate(
      final String userName,
      final String tenantDomain,
      final AuthenticationContext ctx,
      final byte[] data,
      final Map<ClaimMapping, String> claims,
      final X509Certificate cert)
      throws AuthenticationFailedException {

    final boolean isSelfRegistrationEnable =
        Boolean.parseBoolean(
            getAuthenticatorConfig()
                .getParameterMap()
                .get(X509CertificateConstants.ENFORCE_SELF_REGISTRATION_CONFIG_PROPERTY));

    final boolean isUserCertValid;
    try {
      isUserCertValid =
          X509CertificateUtil.validateCertificate(
              userName, tenantDomain, ctx, data, isSelfRegistrationEnable);
    } catch (final AuthenticationFailedException e) {
      if (StringUtils.isEmpty(
          (String)
              ctx.getProperty(
                  X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY))) {
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.X509_CERTIFICATE_NOT_VALIDATED_ERROR_CODE);
      }
      throw new AuthenticationFailedException("Error in validating the user certificate", e);
    }

    if (!isUserCertValid) {
      if (log.isDebugEnabled()) {
        log.debug("X509 certificate validation failed.");
      }
      if (StringUtils.isEmpty(
          (String)
              ctx.getProperty(
                  X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY))) {
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.X509_CERTIFICATE_NOT_VALID_ERROR_CODE);
      }
      throw new AuthenticationFailedException("X509Certificate is not valid");
    }

    final String userStoreDomain =
        X509CertificateUtil.getUserStoreDomainName(userName, tenantDomain, ctx);
    final String qualifiedUserName = addDomainToName(userName, userStoreDomain);
    setupUserContext(tenantDomain, userStoreDomain);

    try {
      // Check whether the user account is disabled or not.
      final AuthenticatedUser userToCheck =
          createAuthenticatedUser(qualifiedUserName, tenantDomain);

      // Check whether the user account is locked or not.
      if (X509CertificateUtil.isAccountLocked(userToCheck)) {
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USER_ACCOUNT_LOCKED_ERROR_CODE);
        throw new AuthenticationFailedException("Account is locked for user: " + qualifiedUserName);
      }

      if (X509CertificateUtil.isAccountDisabled(userToCheck)) {
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USER_ACCOUNT_DISABLED);
        throw new AuthenticationFailedException(
            "Account is disabled for user: " + qualifiedUserName);
      }
    } catch (UserStoreException | AccountLockServiceException e) {
      throw new AuthenticationFailedException(
          "User account lock/disable validation failed for user: " + qualifiedUserName, e);
    }

    allowUser(qualifiedUserName, claims, cert, ctx);
  }

  /** Searches the step map for a previously authenticated local user. */
  private AuthenticatedUser getAuthenticatedUserFromSteps(final AuthenticationContext ctx) {
    final Map<Integer, StepConfig> stepMap = ctx.getSequenceConfig().getStepMap();
    // Searches authentication steps for prior local user
    for (int i = 1; i <= stepMap.size(); i++) {
      final StepConfig stepConfig = stepMap.get(i);
      if (stepConfig.getAuthenticatedUser() != null
          && stepConfig.getAuthenticatedAutenticator().getApplicationAuthenticator()
              instanceof LocalApplicationAuthenticator) {
        return stepConfig.getAuthenticatedUser();
      }
    }
    return null;
  }

  /**
   * Builds a claim map from the certificate's X500 principal RDNs and sets the username property
   * when the configured username attribute is found.
   */
  protected Map<ClaimMapping, String> getSubjectAttributes(
      final AuthenticationContext ctx, final String certAttributes)
      throws AuthenticationFailedException {

    final LdapName ldapDN = parseLdapName(certAttributes);
    final Map<ClaimMapping, String> claims = new HashMap<>();
    final String userNameAttribute =
        getAuthenticatorConfig().getParameterMap().get(X509CertificateConstants.USERNAME);

    if (log.isDebugEnabled()) {
      log.debug("Getting username attribute: " + userNameAttribute);
    }

    for (final Rdn rdn : ldapDN.getRdns()) {
      claims.put(
          ClaimMapping.build(rdn.getType(), rdn.getType(), null, false),
          String.valueOf(rdn.getValue()));

      if (StringUtils.isNotEmpty(userNameAttribute) && userNameAttribute.equals(rdn.getType())) {
        if (log.isDebugEnabled()) {
          log.debug("Setting X509Certificate username attribute: " + userNameAttribute);
        }
        ctx.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_USERNAME_CONTEXT_PROPERTY,
            String.valueOf(rdn.getValue()));
      }
    }
    return claims;
  }

  private void allowUser(
      final String userName,
      final Map<ClaimMapping, String> claims,
      final X509Certificate cert,
      final AuthenticationContext ctx) {

    final String tenantDomain =
        StringUtils.isNotBlank(ctx.getTenantDomain())
            ? ctx.getTenantDomain()
            : X509CertificateConstants.SUPER_TENANT_DOMAIN_NAME;

    final AuthenticatedUser authenticatedUserObj = createAuthenticatedUser(userName, tenantDomain);

    authenticatedUserObj.setAuthenticatedSubjectIdentifier(String.valueOf(cert.getSerialNumber()));
    authenticatedUserObj.setUserAttributes(claims);

    ctx.setSubject(authenticatedUserObj);
  }

  private LdapName parseLdapName(final String certAttributes) throws AuthenticationFailedException {
    try {
      return new LdapName(certAttributes);
    } catch (final InvalidNameException e) {
      throw new AuthenticationFailedException(
          "Error occurred while parsing the certificate subject DN", e);
    }
  }

  private void addMatchStringsToList(final Matcher matcher, final Set<String> matches) {
    while (matcher.find()) {
      matches.add(matcher.group());
    }
  }

  protected String addDomainToName(final String userName, final String userStoreDomain) {
    return UserCoreUtil.addDomainToName(userName, userStoreDomain);
  }

  protected void setupUserContext(final String tenantDomain, final String userStoreDomain) {
    UserCoreUtil.setDomainInThreadLocal(userStoreDomain);
    PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain, true);
  }

  protected AuthenticatedUser createAuthenticatedUser(
      final String userName, final String tenantDomain) {
    final AuthenticatedUser authUser =
        AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(userName);
    authUser.setTenantDomain(tenantDomain);

    return authUser;
  }
}
