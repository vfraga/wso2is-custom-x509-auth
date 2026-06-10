package org.wso2.support.sample.x509authenticator;

/** Constants for the X509 Certificate Authenticator. */
public final class X509CertificateConstants {

  public static final String DEFAULT = "default";
  public static final String SUCCESS = "success";
  public static final String USERNAME = "username";
  public static final String AUTHENTICATORS = "authenticators";

  public static final String AUTHENTICATOR_NAME = "CustomX509CertificateAuthenticator";
  public static final String AUTHENTICATOR_FRIENDLY_NAME = "Custom X509 Certificate Authenticator";

  public static final String AUTHENTICATION_ENDPOINT_CONFIG_PROPERTY = "AuthenticationEndpoint";
  public static final String SESSION_DATA_KEY = "sessionDataKey";

  public static final String X_509_CERTIFICATE = "javax.servlet.request.X509Certificate";
  public static final String X509_CERTIFICATE_SERVLET_URL =
      "https://localhost:8443/x509-certificate-servlet";
  public static final String X509_CERTIFICATE_ERROR_JSP_PATH =
      "x509certificateauthenticationendpoint/x509CertificateError.jsp";

  public static final String SET_CLAIM_URI = "setClaimURI";
  public static final String ACCOUNT_DISABLED_CLAIM_URI =
      "http://wso2.org/claims/identity/accountDisabled";
  public static final String USER_CERTIFICATE_CLAIM_URI = "http://wso2.org/claims/userCertificate";
  public static final String USERNAME_CLAIM_URI = "http://wso2.org/claims/username";

  public static final String USER_NAME_REGEX_CONFIG_PROPERTY = "UsernameRegex";
  public static final String ALTERNATIVE_NAMES_REGEX_CONFIG_PROPERTY = "AlternativeNamesRegex";
  public static final String ENFORCE_SELF_REGISTRATION_CONFIG_PROPERTY = "EnforceSelfRegistration";
  public static final String SEARCH_ALL_USER_STORES_CONFIG_PROPERTY = "SearchAllUserStores";
  public static final String LOGIN_CLAIM_URIS_CONFIG_PROPERTY = "LoginClaimURIs";
  public static final String CHECK_USER_CERT_CLAIM_CONFIG_PROPERTY = "CheckUserCertClaim";

  /**
   * Maps named capture groups of {@code UsernameRegex} to claim URIs, combined with AND when
   * resolving the user. Format: {@code group:claimURI,group:claimURI} (e.g.
   * {@code employeeNumber:http://wso2.org/claims/employeeNumber,region:http://wso2.org/claims/region}).
   * When set, the user is resolved by searching the primary group's claim and disambiguating the
   * remaining candidates against the other groups' claims.
   */
  public static final String COMPOUND_CLAIM_MAPPING_CONFIG_PROPERTY = "CompoundClaimMapping";

  /**
   * Names the {@link #COMPOUND_CLAIM_MAPPING_CONFIG_PROPERTY} group used as the primary lookup key
   * (the always-present, most selective value). Defaults to the first entry in the mapping.
   */
  public static final String PRIMARY_CLAIM_GROUP_CONFIG_PROPERTY = "PrimaryClaimGroup";

  /** Context property: claim URI searched first during compound resolution. */
  public static final String X509_COMPOUND_PRIMARY_CLAIM_URI_CONTEXT_PROPERTY =
      "X509CompoundPrimaryClaimUri";

  /** Context property: value searched against the primary claim during compound resolution. */
  public static final String X509_COMPOUND_PRIMARY_VALUE_CONTEXT_PROPERTY =
      "X509CompoundPrimaryValue";

  /**
   * Context property: serializable {@code Map<claimURI, expectedValue>} of the secondary filters
   * applied (ANDed) to the candidates returned by the primary claim search.
   */
  public static final String X509_COMPOUND_SECONDARY_FILTERS_CONTEXT_PROPERTY =
      "X509CompoundSecondaryFilters";

  public static final String X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY =
      "X509CertificateErrorCode";
  public static final String X509_CERTIFICATE_USERNAME_CONTEXT_PROPERTY = "X509CertificateUsername";
  public static final String X509_CERT_RESOLVED_USERNAME_CONTEXT_PROPERTY =
      "X509CertResolvedUsername";

  public static final String X509_CERTIFICATE_NOT_FOUND_ERROR_CODE = "18013";
  public static final String X509_CERTIFICATE_NOT_VALID_ERROR_CODE = "18015";
  public static final String USERNAME_NOT_FOUND_ON_X509_CERTIFICATE_ATTRIBUTE = "18003";

  public static final String USERNAME_CONFLICT = "20015";
  public static final String USER_NOT_FOUND_ERROR_CODE = "17001";
  public static final String USER_ACCOUNT_LOCKED_ERROR_CODE = "17002";
  public static final String USER_ACCOUNT_DISABLED = "17010";

  public static final String X509_CERTIFICATE_NOT_VALIDATED_ERROR_CODE = "17003";

  public static final String X509_CERTIFICATE_ALT_NAME_MULTIPLE_MATCHES_ERROR_CODE = "17004";
  public static final String X509_CERTIFICATE_ALT_NAME_NO_MATCHES_ERROR_CODE = "17005";
  public static final String X509_CERTIFICATE_ALT_NAME_NOT_FOUND_ERROR_CODE = "17008";
  public static final String X509_CERTIFICATE_SUBJECT_DN_MULTIPLE_MATCHES_ERROR_CODE = "17006";
  public static final String X509_CERTIFICATE_SUBJECT_DN_REGEX_NO_MATCHES_ERROR_CODE = "17007";

  public static final String AUTH_FAILURE_PARAM = "authFailure";
  public static final String ERROR_CODE_PARAM = "errorCode";

  public static final String X509_CERTIFICATE_ALTERNATIVE_NAMES_NOTFOUND_ERROR =
      "Regex Configured but no alternative names in the certificate";
  public static final String X509_CERTIFICATE_SUBJECT_DN_REGEX_NO_MATCHES_ERROR =
      "Regex configured but no matching subjectRDN found for the given regex";
  public static final int MAX_ITEM_LIMIT_UNLIMITED = -1;

  public static final String SUPER_TENANT_DOMAIN_NAME = "carbon.super";

  private X509CertificateConstants() {
    // Prevent instantiation.
  }
}
