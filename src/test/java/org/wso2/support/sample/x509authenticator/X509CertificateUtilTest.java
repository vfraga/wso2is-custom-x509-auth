package org.wso2.support.sample.x509authenticator;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.fail;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.testng.IObjectFactory;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.support.sample.x509authenticator.internal.ServiceHolder;

@PrepareForTest({
  X509CertificateUtil.class,
  FileBasedConfigurationBuilder.class,
  ServiceHolder.class,
  IdentityTenantUtil.class,
  AbstractUserStoreManager.class,
  CertificateFactory.class
})
@PowerMockIgnore({"javax.security.*", "javax.xml.*"})
public class X509CertificateUtilTest {

  @ObjectFactory
  public IObjectFactory getObjectFactory() {
    return new PowerMockObjectFactory();
  }

  private void setupMocks(AuthenticationContext context, Map<String, String> params)
      throws Exception {
    mockStatic(FileBasedConfigurationBuilder.class);
    FileBasedConfigurationBuilder mockBuilder = mock(FileBasedConfigurationBuilder.class);
    when(FileBasedConfigurationBuilder.getInstance()).thenReturn(mockBuilder);

    AuthenticatorConfig authConfig = new AuthenticatorConfig();
    authConfig.setParameterMap(params);
    when(mockBuilder.getAuthenticatorBean(anyString())).thenReturn(authConfig);

    context.setTenantDomain("carbon.super");

    mockStatic(IdentityTenantUtil.class);
    when(IdentityTenantUtil.getTenantId(anyString())).thenReturn(-1234);

    mockStatic(ServiceHolder.class);
    ServiceHolder mockServiceHolder = mock(ServiceHolder.class);
    when(ServiceHolder.getInstance()).thenReturn(mockServiceHolder);
    RealmService mockRealmService = mock(RealmService.class);
    when(mockServiceHolder.getRealmService()).thenReturn(mockRealmService);

    UserRealm mockUserRealm = mock(UserRealm.class);
    when(mockRealmService.getTenantUserRealm(anyInt())).thenReturn(mockUserRealm);

    AbstractUserStoreManager mockUserStoreManager = mock(AbstractUserStoreManager.class);
    when(mockUserRealm.getUserStoreManager()).thenReturn(mockUserStoreManager);
  }

  @Test
  public void testGetFullyQualifiedUsernameConflictAcrossClaims() throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    Map<String, String> params = new HashMap<>();
    params.put(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY, "true");
    params.put(X509CertificateConstants.LOGIN_CLAIM_URIS_CONFIG_PROPERTY, "claim1,claim2");
    setupMocks(context, params);

    UserRealm mockUserRealm =
        ServiceHolder.getInstance().getRealmService().getTenantUserRealm(-1234);
    AbstractUserStoreManager mockUserStoreManager =
        (AbstractUserStoreManager) mockUserRealm.getUserStoreManager();

    String identifier = "test-user";
    when(mockUserStoreManager.listUsers(identifier, -1)).thenReturn(new String[0]);

    // Found in claim1
    when(mockUserStoreManager.getUserList("claim1", identifier, null))
        .thenReturn(new String[] {"user1"});
    // Found in claim2
    when(mockUserStoreManager.getUserList("claim2", identifier, null))
        .thenReturn(new String[] {"user2"});

    try {
      X509CertificateUtil.getResolvedUsername(identifier, context.getTenantDomain(), context);
      fail("Expected AuthenticationFailedException due to conflict across claims");
    } catch (AuthenticationFailedException e) {
      assertEquals(
          context.getProperty(
              X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY),
          X509CertificateConstants.USERNAME_CONFLICT);
    }
  }

  @Test
  public void testGetFullyQualifiedUsernameNotFoundReturnsNull() throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    Map<String, String> params = new HashMap<>();
    params.put(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY, "true");
    setupMocks(context, params);

    UserRealm mockUserRealm =
        ServiceHolder.getInstance().getRealmService().getTenantUserRealm(-1234);
    AbstractUserStoreManager mockUserStoreManager =
        (AbstractUserStoreManager) mockUserRealm.getUserStoreManager();

    when(mockUserStoreManager.listUsers(anyString(), anyInt())).thenReturn(new String[0]);
    when(mockUserStoreManager.getUserList(anyString(), anyString(), Matchers.any()))
        .thenReturn(new String[0]);

    String result =
        X509CertificateUtil.getResolvedUsername("non-existent", context.getTenantDomain(), context);
    assertNull(result);
    assertEquals(
        context.getProperty(X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY),
        X509CertificateConstants.USER_NOT_FOUND_ERROR_CODE);
  }

  @Test
  public void testGetFullyQualifiedUsernameConflictBetweenUsernameAndClaim() throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    Map<String, String> params = new HashMap<>();
    params.put(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY, "true");
    params.put(X509CertificateConstants.LOGIN_CLAIM_URIS_CONFIG_PROPERTY, "claim1");
    setupMocks(context, params);

    UserRealm mockUserRealm =
        ServiceHolder.getInstance().getRealmService().getTenantUserRealm(-1234);
    AbstractUserStoreManager mockUserStoreManager =
        (AbstractUserStoreManager) mockUserRealm.getUserStoreManager();

    String identifier = "bob";
    // Matches "userA" as username
    when(mockUserStoreManager.listUsers(identifier, -1)).thenReturn(new String[] {"userA"});
    // Matches "userB" as claim value
    when(mockUserStoreManager.getUserList("claim1", identifier, null))
        .thenReturn(new String[] {"userB"});

    try {
      X509CertificateUtil.getResolvedUsername(identifier, context.getTenantDomain(), context);
      fail("Expected AuthenticationFailedException due to conflict between username and claim");
    } catch (AuthenticationFailedException e) {
      assertEquals(
          context.getProperty(
              X509CertificateConstants.X509_CERTIFICATE_ERROR_CODE_CONTEXT_PROPERTY),
          X509CertificateConstants.USERNAME_CONFLICT);
    }
  }

  @Test
  public void testValidateCertificateBindingEnforcedEvenIfSelfRegDisabled() throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    setupMocks(context, new HashMap<>());

    X509Certificate storedCert = mock(X509Certificate.class);
    X509Certificate presentedCert = mock(X509Certificate.class);

    mockStatic(CertificateFactory.class);
    CertificateFactory mockFactory = mock(CertificateFactory.class);
    when(CertificateFactory.getInstance("X509")).thenReturn(mockFactory);
    when(mockFactory.generateCertificate(any(InputStream.class))).thenReturn(presentedCert);

    PowerMockito.spy(X509CertificateUtil.class);
    PowerMockito.doReturn(storedCert)
        .when(X509CertificateUtil.class, "getCertificate", anyString(), anyString());

    // Binding verification should fail as certificates are different
    boolean result =
        X509CertificateUtil.validateCertificate(
            "test-user", context.getTenantDomain(), context, new byte[0], false);
    assertFalse(
        result,
        "Should fail validation if stored certificate doesn't match presented one, even if self-reg is disabled");
  }

  @Test
  public void testGetFullyQualifiedUsernameClaimSearchWhenSearchAllUserStoresFalse()
      throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    Map<String, String> params = new HashMap<>();
    params.put(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY, "false");
    params.put(X509CertificateConstants.LOGIN_CLAIM_URIS_CONFIG_PROPERTY, "claim1");
    setupMocks(context, params);

    UserRealm mockUserRealm =
        ServiceHolder.getInstance().getRealmService().getTenantUserRealm(-1234);
    AbstractUserStoreManager mockUserStoreManager =
        (AbstractUserStoreManager) mockUserRealm.getUserStoreManager();

    String identifier = "test-user";
    when(mockUserStoreManager.isExistingUser(identifier)).thenReturn(false);
    // It should fall back to search by claims even if SearchAllUserStores is false
    when(mockUserStoreManager.getUserList("claim1", identifier, null))
        .thenReturn(new String[] {"user1"});

    String result =
        X509CertificateUtil.getResolvedUsername(identifier, context.getTenantDomain(), context);
    assertEquals(
        result, "user1", "Should have searched by claims even when SearchAllUserStores is false");
  }

  @Test
  public void testGetUserStoreDomainNameWhenNoDomainInIdentifier() throws Exception {
    AuthenticationContext context = new AuthenticationContext();
    Map<String, String> params = new HashMap<>();
    params.put(X509CertificateConstants.SEARCH_ALL_USER_STORES_CONFIG_PROPERTY, "true");
    setupMocks(context, params);

    UserRealm mockUserRealm =
        ServiceHolder.getInstance().getRealmService().getTenantUserRealm(-1234);
    AbstractUserStoreManager mockUserStoreManager =
        (AbstractUserStoreManager) mockUserRealm.getUserStoreManager();

    String identifier = "bob";
    // bob exists in the "SECONDARY" domain
    when(mockUserStoreManager.listUsers(identifier, -1)).thenReturn(new String[] {"SECONDARY/bob"});

    String domain =
        X509CertificateUtil.getUserStoreDomainName(identifier, context.getTenantDomain(), context);
    assertEquals(
        domain,
        "SECONDARY",
        "Domain should be resolved from the user store if not present in identifier");
  }
}
