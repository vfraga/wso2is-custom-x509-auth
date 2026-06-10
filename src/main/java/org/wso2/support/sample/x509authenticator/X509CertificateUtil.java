package org.wso2.support.sample.x509authenticator;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.x509Certificate.validation.CertificateValidationException;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManager;
import org.wso2.carbon.identity.x509Certificate.validation.service.RevocationValidationManagerImpl;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.support.sample.x509authenticator.internal.ServiceHolder;

/** Utility helpers for certificate retrieval, storage, and validation against the user store. */
public final class X509CertificateUtil {

  private static final Log log = LogFactory.getLog(X509CertificateUtil.class);
  private static final String CERT_TYPE = "X509";
  private static final RevocationValidationManager revocationValidationManager =
      new RevocationValidationManagerImpl();

  private X509CertificateUtil() {
    // Utility class — prevent instantiation.
  }

  /**
   * Retrieves the X509 certificate stored in the user's claim.
   *
   * @param username the username
   * @param tenantDomain the tenant domain
   * @return the stored certificate, or {@code null} if no certificate claim exists
   * @throws AuthenticationFailedException on realm / certificate errors
   */
  public static X509Certificate getCertificate(final String username, final String tenantDomain)
      throws AuthenticationFailedException {

    final String checkUserCertClaim =
        getX509Parameters().get(X509CertificateConstants.CHECK_USER_CERT_CLAIM_CONFIG_PROPERTY);
    if (!Boolean.parseBoolean(checkUserCertClaim)) {
      log.debug(
          "CheckUserCertClaim is set to false, skipping user certificate claim retrieval for user");
      return null;
    }

    final UserStoreManager userStoreManager = getRequiredUserStoreManager(tenantDomain);
    final String userCertificateClaimUri = getUserCertificateClaimUri();

    try {

      log.debug("Retrieving X509Certificate from user claim: " + userCertificateClaimUri);

      final Map<String, String> claimValues =
          userStoreManager.getUserClaimValues(
              username, new String[] {userCertificateClaimUri}, null);
      final String userCertificate = claimValues.get(userCertificateClaimUri);

      // Avoid logging raw certificate value. Log only presence and size to aid debugging.
      log.debug(
          "User certificate claim present: "
              + StringUtils.isNotEmpty(userCertificate)
              + " (len="
              + (userCertificate != null ? userCertificate.length() : 0)
              + ")");
      if (StringUtils.isEmpty(userCertificate)) {
        return null;
      }

      return (X509Certificate)
          getCertificateFactory()
              .generateCertificate(
                  new ByteArrayInputStream(Base64.getMimeDecoder().decode(userCertificate)));
    } catch (final CertificateException e) {
      throw new AuthenticationFailedException("Error while decoding the certificate", e);
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException(
          "Error while retrieving the user certificate data", e);
    }
  }

  /**
   * Stores the given certificate as a user claim.
   *
   * @param username the username
   * @param tenantDomain the tenant domain
   * @param x509Certificate the certificate to store
   * @throws AuthenticationFailedException on realm / certificate errors
   */
  public static void addCertificate(
      final String username, final String tenantDomain, final X509Certificate x509Certificate)
      throws AuthenticationFailedException {

    final UserStoreManager userStoreManager = getRequiredUserStoreManager(tenantDomain);

    try {
      final Map<String, String> claims = new HashMap<>();
      final String userCertificateClaimUri = getUserCertificateClaimUri();

      claims.put(
          userCertificateClaimUri,
          Base64.getEncoder().encodeToString(x509Certificate.getEncoded()));

      log.debug("Adding X509Certificate to user claim: " + userCertificateClaimUri);

      userStoreManager.setUserClaimValues(username, claims, X509CertificateConstants.DEFAULT);
    } catch (final CertificateException e) {
      throw new AuthenticationFailedException("Error while encoding certificate for storage", e);
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException("Error while storing certificate in user store", e);
    }

    // Do not log the username to avoid exposing PII in logs.
    log.debug("X509 certificate was added to user claim for tenant: " + tenantDomain);
  }

  /**
   * Validates the presented certificate bytes against the user store (existence, revocation,
   * self-registration enrollment).
   *
   * @param userName the username
   * @param tenantDomain the tenant domain
   * @param authenticationContext the current authentication context
   * @param certificateBytes DER-encoded certificate bytes
   * @param isSelfRegistrationEnable whether self-registration flow is active
   * @return {@code true} if the certificate is valid
   * @throws AuthenticationFailedException on any validation error
   */
  public static boolean validateCertificate(
      final String userName,
      final String tenantDomain,
      final AuthenticationContext authenticationContext,
      final byte[] certificateBytes,
      final boolean isSelfRegistrationEnable)
      throws AuthenticationFailedException {

    final X509Certificate x509Certificate;
    try {
      x509Certificate =
          (X509Certificate)
              getCertificateFactory()
                  .generateCertificate(new ByteArrayInputStream(certificateBytes));
    } catch (final CertificateException e) {
      throw new AuthenticationFailedException("Error while retrieving certificate", e);
    }

    log.debug(
        "Starting X509 certificate validation. Tenant: "
            + tenantDomain
            + ", self-registration enabled: "
            + isSelfRegistrationEnable);
    try {
      final X509Certificate certInUserClaim = getCertificate(userName, tenantDomain);
      if (certInUserClaim != null) {
        if (!x509Certificate.equals(certInUserClaim)) {
          log.debug("The presented certificate does not match the one stored in the user claim.");
          return false;
        }
      } else if (!isSelfRegistrationEnable
          && !isUserExists(userName, tenantDomain, authenticationContext)) {
        log.debug("User does not exist and self-registration is disabled.");
        return false;
      }

      if (isCertificateRevoked(x509Certificate)) {
        if (log.isDebugEnabled()) {
          log.debug(
              "X509 certificate with serial num: "
                  + x509Certificate.getSerialNumber()
                  + " is revoked");
        }
        if (isSelfRegistrationEnable) {
          deleteUserCertificate(userName, tenantDomain, x509Certificate, certInUserClaim);
        }
        return false;
      }

      if (isSelfRegistrationEnable && certInUserClaim == null) {
        addUserCertificate(userName, tenantDomain, x509Certificate);
      }
    } catch (final CertificateValidationException e) {
      throw new AuthenticationFailedException(
          "Error while validating client certificate with serial num: "
              + x509Certificate.getSerialNumber(),
          e);
    }
    return true;
  }

  /** Reads authenticator parameters from the file-based configuration. */
  public static Map<String, String> getX509Parameters() {
    final AuthenticatorConfig authConfig =
        FileBasedConfigurationBuilder.getInstance()
            .getAuthenticatorBean(X509CertificateConstants.AUTHENTICATOR_NAME);
    if (authConfig != null) {
      return authConfig.getParameterMap();
    }
    log.debug(
        "AuthenticatorConfig is not provided for " + X509CertificateConstants.AUTHENTICATOR_NAME);
    return Collections.emptyMap();
  }

  /** Resolves the claim URI used to store the user certificate. */
  public static String getUserCertificateClaimUri() {
    final String setClaimUriConfig =
        getX509Parameters().get(X509CertificateConstants.SET_CLAIM_URI);
    if (setClaimUriConfig != null) {
      return setClaimUriConfig;
    }
    return X509CertificateConstants.USER_CERTIFICATE_CLAIM_URI;
  }

  /**
   * Resolves the {@link UserRealm} for the given tenant domain.
   *
   * @param tenantDomain the tenant domain
   * @return the realm (never {@code null})
   * @throws AuthenticationFailedException if the realm cannot be resolved
   */
  public static UserRealm getUserRealm(final String tenantDomain)
      throws AuthenticationFailedException {
    log.debug("Getting user realm for tenantDomain: " + tenantDomain);
    try {
      final int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
      final RealmService realmService = ServiceHolder.getInstance().getRealmService();
      return realmService.getTenantUserRealm(tenantId);
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException(
          "Cannot find the user realm for the tenantDomain: " + tenantDomain, e);
    }
  }

  /**
   * Retrieves the {@link UserStoreManager} for the given tenant, throwing immediately if the realm
   * is {@code null}.
   */
  private static UserStoreManager getRequiredUserStoreManager(final String tenantDomain)
      throws AuthenticationFailedException {

    final UserRealm userRealm = getUserRealm(tenantDomain);
    if (userRealm == null) {
      throw new AuthenticationFailedException(
          "Cannot find the user realm for the given tenant domain: " + tenantDomain);
    }
    try {
      return userRealm.getUserStoreManager();
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException(
          "Error while retrieving the user store manager for tenant: " + tenantDomain, e);
    }
  }

  private static boolean isCertificateRevoked(final X509Certificate x509Certificate)
      throws CertificateValidationException {

    return revocationValidationManager.verifyRevocationStatus(x509Certificate);
  }

  private static void deleteUserCertificate(
      final String userName,
      final String tenantDomain,
      final X509Certificate x509Certificate,
      final X509Certificate certInUserClaim)
      throws AuthenticationFailedException {

    if (!x509Certificate.equals(certInUserClaim)) {
      return;
    }

    if (log.isDebugEnabled()) {
      log.debug(
          "Provided X509 client certificate with serial num: "
              + x509Certificate.getSerialNumber()
              + " has been revoked. Removing the X509 certificate claim for the affected user.");
    }
    deleteCertificate(userName, tenantDomain);
  }

  private static void deleteCertificate(final String username, final String tenantDomain)
      throws AuthenticationFailedException {

    final UserStoreManager userStoreManager = getRequiredUserStoreManager(tenantDomain);
    final String userCertificateClaimUri = getUserCertificateClaimUri();
    final String[] claims = {userCertificateClaimUri};

    try {
      log.debug("Deleting X509Certificate from user claim: " + userCertificateClaimUri);

      userStoreManager.deleteUserClaimValues(username, claims, X509CertificateConstants.DEFAULT);
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException(
          "Error while deleting certificate of " + username + " in tenant: " + tenantDomain, e);
    }
    log.debug("X509 certificate claim deleted for " + username + " in tenant: " + tenantDomain);
  }

  private static void addUserCertificate(
      final String userName, final String tenantDomain, final X509Certificate x509Certificate)
      throws AuthenticationFailedException {

    if (log.isDebugEnabled()) {
      log.debug(
          "X509 Certificate with serial num: "
              + x509Certificate.getSerialNumber()
              + " does not exist for the user. Proceeding to add it to the user claim. Tenant: "
              + tenantDomain);
    }
    addCertificate(userName, tenantDomain, x509Certificate);
    if (log.isDebugEnabled()) {
      log.debug(
          "Adding the X509 certificate with serial num: "
              + x509Certificate.getSerialNumber()
              + " as a user claim.");
    }
  }

  /**
   * Checks if the user exists in the user store.
   *
   * @param userName the username
   * @param tenantDomain the tenant domain
   * @param authenticationContext the authentication context
   * @return true if the user exists, false otherwise
   * @throws AuthenticationFailedException if an error occurs while checking the user existence
   */
  public static boolean isUserExists(
      final String userName,
      final String tenantDomain,
      final AuthenticationContext authenticationContext)
      throws AuthenticationFailedException {

    return getFullyQualifiedUsername(userName, tenantDomain, authenticationContext) != null;
  }

  /**
   * Resolves the username from the given identifier.
   *
   * @param identifier the identifier
   * @param tenantDomain the tenant domain
   * @param authenticationContext the authentication context
   * @return the resolved username
   * @throws AuthenticationFailedException if the user cannot be resolved or is conflicting
   */
  public static String getResolvedUsername(
      final String identifier,
      final String tenantDomain,
      final AuthenticationContext authenticationContext)
      throws AuthenticationFailedException {

    return getFullyQualifiedUsername(identifier, tenantDomain, authenticationContext);
  }

  /**
   * Resolves the user store domain name for the given user identifier.
   *
   * @param userIdentifier the user identifier
   * @param tenantDomain the tenant domain
   * @param authenticationContext the authentication context
   * @return the user store domain name
   * @throws AuthenticationFailedException if the domain cannot be resolved
   */
  public static String getUserStoreDomainName(
      final String userIdentifier,
      final String tenantDomain,
      final AuthenticationContext authenticationContext)
      throws AuthenticationFailedException {

    if (StringUtils.isNotBlank(userIdentifier)
        && userIdentifier.indexOf(UserCoreConstants.DOMAIN_SEPARATOR) > 0) {
      return UserCoreUtil.extractDomainFromName(userIdentifier);
    }

    final String fullyQualifiedName =
        getFullyQualifiedUsername(userIdentifier, tenantDomain, authenticationContext);
    if (StringUtils.isNotBlank(fullyQualifiedName)) {
      return UserCoreUtil.extractDomainFromName(fullyQualifiedName);
    }
    return UserCoreUtil.extractDomainFromName(userIdentifier);
  }

  private static String getFullyQualifiedUsername(
      final String identifier, final String tenantDomain, final AuthenticationContext context)
      throws AuthenticationFailedException {

    final String cacheKey =
        X509CertificateConstants.X509_CERT_RESOLVED_USERNAME_CONTEXT_PROPERTY + "_" + identifier;
    final Object cached = context.getProperty(cacheKey);

    if (cached instanceof String) return (String) cached;

    // Compound (AND) claim resolution: when the authenticator has stashed a compound search spec,
    // resolve by searching the primary claim and disambiguating the candidates against the
    // remaining claims, instead of the single-value (OR) strategy below.
    final Object primaryClaimUriObj =
        context.getProperty(
            X509CertificateConstants.X509_COMPOUND_PRIMARY_CLAIM_URI_CONTEXT_PROPERTY);
    if (primaryClaimUriObj instanceof String && StringUtils.isNotEmpty((String) primaryClaimUriObj)) {
      final String resolved =
          resolveByCompoundClaims((String) primaryClaimUriObj, tenantDomain, context);
      if (resolved == null
          && context.getProperty(
                  X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY)
              == null) {
        context.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USER_NOT_FOUND_ERROR_CODE);
        log.warn("User not resolved by compound claim search");
      }
      if (resolved != null) {
        context.setProperty(cacheKey, resolved);
        final String resolvedCacheKey =
            X509CertificateConstants.X509_CERT_RESOLVED_USERNAME_CONTEXT_PROPERTY + "_" + resolved;
        if (!cacheKey.equals(resolvedCacheKey)) {
          context.setProperty(resolvedCacheKey, resolved);
        }
        log.debug("User resolved successfully via compound claim search");
      }
      return resolved;
    }

    final Map<String, String> params = getX509Parameters();
    String fullyQualifiedUsername = null;

    // Log the resolution strategy being used
    if (log.isDebugEnabled()) {
      log.debug(
          "Resolving user for identifier. SearchAllUserStores=["
              + params.get(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY)
              + "], LoginClaimURIs=["
              + params.get(X509CertificateConstants.LOGIN_CLAIM_URIS_CONFIG_PROPERTY)
              + "]");
    }

    try {
      final UserStoreManager userStoreManager = getRequiredUserStoreManager(tenantDomain);

      if (Boolean.parseBoolean(
          params.get(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY))) {
        final String[] filteredUsers =
            userStoreManager.listUsers(
                identifier, X509CertificateConstants.MAX_ITEM_LIMIT_UNLIMITED);
        // Assigns username if unique; throws on conflicts
        if (filteredUsers != null && filteredUsers.length == 1) {
          fullyQualifiedUsername = filteredUsers[0];
          log.debug("SearchAllUserStores: exactly 1 user found");
        } else if (filteredUsers != null && filteredUsers.length > 1) {
          context.setProperty(
              X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
              X509CertificateConstants.USERNAME_CONFLICT);
          log.debug(
              "Conflicting users found for the given identifier. SearchAllUserStores: "
                  + filteredUsers.length
                  + " conflicting users found");
          throw new AuthenticationFailedException(
              "Conflicting users found for the given identifier.");
        } else if (filteredUsers != null) {
          // No users matched in any user store
          log.debug("SearchAllUserStores: no users found matching the identifier");
        }
      } else {
        if (userStoreManager.isExistingUser(identifier)) {
          fullyQualifiedUsername = identifier;
        }
      }

      // Fallback to searching by LoginClaimURIs and check for conflicts
      String loginClaimUris = params.get(X509CertificateConstants.LOGIN_CLAIM_URIS_CONFIG_PROPERTY);
      if (StringUtils.isBlank(loginClaimUris)) {
        loginClaimUris = X509CertificateConstants.USERNAME_CLAIM_URI;
      }
      final String resolvedFromClaims =
          resolveByMultiAttribute(identifier, context, loginClaimUris, tenantDomain);

      if (resolvedFromClaims != null) {
        log.debug("Claim-based resolution found a user");
      } else {
        log.debug("Claim-based resolution found no user");
      }

      if (fullyQualifiedUsername != null
          && resolvedFromClaims != null
          && !fullyQualifiedUsername.equals(resolvedFromClaims)) {
        context.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USERNAME_CONFLICT);
        log.debug("Conflicting users found for the given identifier.");
        throw new AuthenticationFailedException(
            "Conflicting users found for the given identifier.");
      }

      if (fullyQualifiedUsername == null) {
        fullyQualifiedUsername = resolvedFromClaims;
        log.debug("Using claim-based resolution result as final username");
      }

      if (fullyQualifiedUsername == null
          && context.getProperty(
                  X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY)
              == null) {
        context.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USER_NOT_FOUND_ERROR_CODE);
      }
      // Warn operators that user resolution failed across all strategies
      if (fullyQualifiedUsername == null) {
        log.warn(
            "User not resolved by any method (SearchAllUserStores and LoginClaimURIs both failed to find a unique match)");
      }
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException("Error while resolving fully qualified username", e);
    }

    if (fullyQualifiedUsername != null) {
      context.setProperty(cacheKey, fullyQualifiedUsername);
      final String resolvedCacheKey =
          X509CertificateConstants.X509_CERT_RESOLVED_USERNAME_CONTEXT_PROPERTY
              + "_"
              + fullyQualifiedUsername;
      if (!cacheKey.equals(resolvedCacheKey)) {
        context.setProperty(resolvedCacheKey, fullyQualifiedUsername);
      }
      log.debug("User resolved successfully");
    }
    return fullyQualifiedUsername;
  }

  public static String buildRedirectURL(
      final String errorPageUrl, final Map<String, String> queryParams, final String ctxQueryParams)
      throws IOException {
    String redirectUrl;
    try {
      redirectUrl = FrameworkUtils.buildURLWithQueryParams(errorPageUrl, queryParams);
      if (StringUtils.isNotEmpty(ctxQueryParams)) {
        redirectUrl = FrameworkUtils.appendQueryParamsStringToUrl(redirectUrl, ctxQueryParams);
      }
    } catch (UnsupportedEncodingException e) {
      throw new IOException("Error while building redirect URL", e);
    }
    return redirectUrl;
  }

  private static String resolveByMultiAttribute(
      final String identifier,
      final AuthenticationContext context,
      final String loginClaimURIs,
      final String tenantDomain)
      throws UserStoreException, AuthenticationFailedException {

    final String[] claimUris = loginClaimURIs.split(",");
    final AbstractUserStoreManager um =
        (AbstractUserStoreManager) getRequiredUserStoreManager(tenantDomain);

    log.debug("Searching for user by claim URIs: [" + loginClaimURIs + "]");

    String resolvedUser = null;
    for (final String claimUri : claimUris) {
      final String[] usersWithClaim = um.getUserList(claimUri, identifier, null);
      if (usersWithClaim != null && usersWithClaim.length > 0) {
        if (usersWithClaim.length > 1
            || (resolvedUser != null && !resolvedUser.equals(usersWithClaim[0]))) {
          context.setProperty(
              X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
              X509CertificateConstants.USERNAME_CONFLICT);
          if (log.isDebugEnabled()) {
            log.debug(
                "Claim URI '"
                    + claimUri
                    + "' returned "
                    + usersWithClaim.length
                    + " users (conflict detected, resolvedUserMatchingClaim="
                    + (resolvedUser != null && resolvedUser.equals(usersWithClaim[0]))
                    + ")");
          }
          throw new AuthenticationFailedException("Conflicting users with the given claim value.");
        }
        resolvedUser = usersWithClaim[0];
        log.debug("Claim URI '" + claimUri + "' returned 1 user");
      } else {
        log.debug("Claim URI '" + claimUri + "' returned no users");
      }
    }

    return resolvedUser;
  }

  /**
   * Resolves a single user by combining multiple claim values with AND semantics.
   *
   * <p>The primary claim is searched first (the always-present, most selective value); the
   * resulting candidates are then narrowed by comparing each remaining claim against the expected
   * value extracted from the certificate. The primary value and the secondary {@code claimURI ->
   * expectedValue} filters are read from the {@link AuthenticationContext} (stashed by the
   * authenticator). Only claim-based user-store APIs are used, so this works uniformly across
   * JDBC and LDAP/AD user stores.
   *
   * @param primaryClaimUri the claim URI searched first
   * @param tenantDomain the tenant domain
   * @param context the authentication context holding the compound search spec
   * @return the single resolved (domain-qualified) username, or {@code null} if none matched
   * @throws AuthenticationFailedException if more than one user matches all filters (conflict) or
   *     on user-store errors
   */
  @SuppressWarnings("unchecked")
  private static String resolveByCompoundClaims(
      final String primaryClaimUri,
      final String tenantDomain,
      final AuthenticationContext context)
      throws AuthenticationFailedException {

    final Object primaryValueObj =
        context.getProperty(X509CertificateConstants.X509_COMPOUND_PRIMARY_VALUE_CONTEXT_PROPERTY);
    final String primaryValue = primaryValueObj instanceof String ? (String) primaryValueObj : null;
    if (StringUtils.isEmpty(primaryValue)) {
      log.debug("Compound resolution: primary value is empty; cannot resolve");
      return null;
    }

    final Object filtersObj =
        context.getProperty(
            X509CertificateConstants.X509_COMPOUND_SECONDARY_FILTERS_CONTEXT_PROPERTY);
    final Map<String, String> secondaryFilters =
        filtersObj instanceof Map ? (Map<String, String>) filtersObj : Collections.emptyMap();

    final AbstractUserStoreManager userStoreManager =
        (AbstractUserStoreManager) getRequiredUserStoreManager(tenantDomain);

    try {
      // Claim search maps the claim URI to the underlying attribute per user store and spans all
      // user stores when no domain is embedded in the value.
      final String[] candidates = userStoreManager.getUserList(primaryClaimUri, primaryValue, null);
      if (candidates == null || candidates.length == 0) {
        log.debug("Compound resolution: primary claim search returned no candidates");
        return null;
      }
      log.debug(
          "Compound resolution: primary claim search returned "
              + candidates.length
              + " candidate(s); applying "
              + secondaryFilters.size()
              + " secondary filter(s)");

      if (secondaryFilters.isEmpty()) {
        // Nothing to disambiguate with; behaves like a single-claim search.
        if (candidates.length == 1) {
          return candidates[0];
        }
        context.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USERNAME_CONFLICT);
        throw new AuthenticationFailedException(
            "Conflicting users found for the given identifier.");
      }

      final String[] secondaryClaimUris = secondaryFilters.keySet().toArray(new String[0]);
      final List<String> matched = new ArrayList<>();
      for (final String candidate : candidates) {
        final Map<String, String> values =
            userStoreManager.getUserClaimValues(candidate, secondaryClaimUris, null);
        boolean allMatch = true;
        for (final Map.Entry<String, String> filter : secondaryFilters.entrySet()) {
          if (!claimValueMatches(filter.getValue(), values.get(filter.getKey()))) {
            allMatch = false;
            break;
          }
        }
        if (allMatch) {
          matched.add(candidate);
        }
      }

      if (matched.isEmpty()) {
        log.debug("Compound resolution: no candidate matched all secondary filters");
        return null;
      }
      if (matched.size() > 1) {
        context.setProperty(
            X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY,
            X509CertificateConstants.USERNAME_CONFLICT);
        log.debug(
            "Compound resolution: "
                + matched.size()
                + " candidates matched all filters (conflict)");
        throw new AuthenticationFailedException(
            "Conflicting users found for the given identifier.");
      }

      log.debug("Compound resolution: resolved to a single user");
      return matched.get(0);
    } catch (final UserStoreException e) {
      throw new AuthenticationFailedException("Error while resolving user by compound claims", e);
    }
  }

  /**
   * Compares an expected claim value against a candidate user's value. {@code null} and empty are
   * treated as equivalent (so an absent/empty attribute matches an empty expected value), and the
   * comparison is trimmed and case-insensitive.
   */
  private static boolean claimValueMatches(final String expected, final String actual) {
    final String e = expected == null ? "" : expected.trim();
    final String a = actual == null ? "" : actual.trim();
    return e.equalsIgnoreCase(a);
  }

  private static CertificateFactory getCertificateFactory() throws CertificateException {
    return CertificateFactoryHolder.INSTANCE;
  }

  /**
   * Check whether the user account is locked or not.
   *
   * @param user Authenticated user.
   * @return boolean account locked or not.
   * @throws AccountLockServiceException if an error occurs when calling the account-lock service.
   */
  public static boolean isAccountLocked(final User user) throws AccountLockServiceException {

    if (user != null) {
      try {
        return ServiceHolder.getInstance()
            .getAccountLockService()
            .isAccountLocked(user.getUserName(), user.getTenantDomain(), user.getUserStoreDomain());
      } catch (AccountLockServiceException e) {
        log.debug("Error while calling the account lock service for user ", e);
        throw e;
      }
    }
    return false;
  }

  /**
   * Check whether the user account is disabled or not.
   *
   * @param user Authenticated user.
   * @return boolean account disabled or not.
   * @throws UserStoreException User store exception.
   */
  public static boolean isAccountDisabled(final User user) throws UserStoreException {

    if (user != null) {
      final String tenantDomain = user.getTenantDomain();
      try {
        final UserStoreManager userStoreManager = getRequiredUserStoreManager(tenantDomain);
        final Map<String, String> values =
            userStoreManager.getUserClaimValues(
                IdentityUtil.addDomainToName(user.getUserName(), user.getUserStoreDomain()),
                new String[] {X509CertificateConstants.ACCOUNT_DISABLED_CLAIM_URI},
                UserCoreConstants.DEFAULT_PROFILE);
        return Boolean.parseBoolean(
            values.get(X509CertificateConstants.ACCOUNT_DISABLED_CLAIM_URI));
      } catch (UserStoreException | AuthenticationFailedException e) {
        log.debug("Error while checking account disable for user.", e);
        throw new UserStoreException(e);
      }
    }
    return false;
  }

  /**
   * Holder for the CertificateFactory singleton. Uses the Initialization-on-demand holder idiom for
   * thread-safe lazy loading.
   */
  private static class CertificateFactoryHolder {
    private static final CertificateFactory INSTANCE;

    static {
      try {
        INSTANCE = CertificateFactory.getInstance(CERT_TYPE);
      } catch (CertificateException e) {
        throw new ExceptionInInitializerError(e);
      }
    }
  }
}
