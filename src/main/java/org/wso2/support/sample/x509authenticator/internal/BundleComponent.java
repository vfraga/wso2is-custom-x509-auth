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

      final String canonicalName = serviceInstance.getClass().getCanonicalName();
      final String serviceName = serviceClass.getName();

      if (registrationResult == null) {
        log.error(
            "Error registering "
                + canonicalName
                + " as a "
                + serviceName
                + ". Service registration result is null.");
      } else {
        log.info(canonicalName + " successfully registered as a " + serviceName + ".");
      }
    } catch (final Exception e) {
      log.error(
          "Error registering "
              + serviceInstance.getClass().getCanonicalName()
              + " as a "
              + serviceClass.getName()
              + ". Service registration failed.",
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
    log.debug("Setting the Realm Service.");

    ServiceHolder.getInstance().setRealmService(realmService);
  }

  protected void unsetRealmService(final RealmService ignored) {
    log.debug("Unsetting the Realm Service.");

    ServiceHolder.getInstance().setRealmService(null);
  }

  @Reference(
      name = "accountLockService",
      service = AccountLockService.class,
      cardinality = ReferenceCardinality.MANDATORY,
      policy = ReferencePolicy.DYNAMIC,
      unbind = "unsetAccountLockService")
  protected void setAccountLockService(final AccountLockService accountLockService) {
    log.debug("Setting the Account Lock Service.");

    ServiceHolder.getInstance().setAccountLockService(accountLockService);
  }

  protected void unsetAccountLockService(final AccountLockService ignored) {
    log.debug("Unsetting the Account Lock Service.");

    ServiceHolder.getInstance().setAccountLockService(null);
  }
}
