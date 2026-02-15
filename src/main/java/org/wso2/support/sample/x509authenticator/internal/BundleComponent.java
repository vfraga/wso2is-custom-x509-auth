package org.wso2.support.sample.x509authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.support.sample.x509authenticator.X509CertificateAuthenticator;

@Component(name = "custom.authenticator.bundle", immediate = true)
public class BundleComponent {
  private static final Log log = LogFactory.getLog(BundleComponent.class);

  private static void registerService(
      final ComponentContext context, final Class<?> serviceClass, final Object serviceInstance) {
    final ServiceRegistration<?> registrationResult;

    try {
      registrationResult =
          context.getBundleContext().registerService(serviceClass.getName(), serviceInstance, null);

      if (registrationResult == null) {
        log.error(
            String.format(
                "Error registering %s as a %s. Service registration result is null.",
                serviceInstance.getClass().getCanonicalName(), serviceClass.getName()));
      } else {
        log.info(
            String.format(
                "%s successfully registered as a %s.",
                serviceInstance.getClass().getCanonicalName(), serviceClass.getName()));
      }
    } catch (final Exception e) {
      log.error(
          String.format(
              "Error registering %s as a %s. Service registration failed.",
              serviceInstance.getClass().getCanonicalName(), serviceClass.getName()),
          e);
    }
  }

  @Activate
  protected void activate(final ComponentContext context) {
    registerService(context, ApplicationAuthenticator.class, new X509CertificateAuthenticator());

    log.info("Custom Authenticator bundle activated.");
  }

  @Deactivate
  protected void deactivate(final ComponentContext ignored) {
    log.info("Custom bundle deactivated.");
  }

  @Reference(
      name = "RealmService",
      service = RealmService.class,
      cardinality = ReferenceCardinality.MANDATORY,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetRealmService")
  protected void setRealmService(final RealmService realmService) {
    if (log.isDebugEnabled()) log.debug("Setting the Realm Service.");

    ServiceHolder.getInstance().setRealmService(realmService);
  }

  protected void unsetRealmService(final RealmService ignored) {
    if (log.isDebugEnabled()) log.debug("Unsetting the Realm Service.");

    ServiceHolder.getInstance().setRealmService(null);
  }

  @Reference(
      name = "accountLockService",
      service = AccountLockService.class,
      cardinality = ReferenceCardinality.MANDATORY,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetAccountLockService")
  protected void setAccountLockService(final AccountLockService accountLockService) {
    if (log.isDebugEnabled()) log.debug("Setting the Account Lock Service.");

    ServiceHolder.getInstance().setAccountLockService(accountLockService);
  }

  protected void unsetAccountLockService(final AccountLockService ignored) {
    if (log.isDebugEnabled()) log.debug("Unsetting the Account Lock Service.");

    ServiceHolder.getInstance().setAccountLockService(null);
  }
}
