package org.wso2.support.sample.x509authenticator.internal;

import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;

public final class ServiceHolder {

  private static final ServiceHolder dataHolder = new ServiceHolder();

  private volatile RealmService realmService;
  private volatile AccountLockService accountLockService;

  private ServiceHolder() {}

  public static ServiceHolder getInstance() {
    return dataHolder;
  }

  public RealmService getRealmService() {
    return realmService;
  }

  public void setRealmService(RealmService realmService) {
    this.realmService = realmService;
  }

  public AccountLockService getAccountLockService() {
    return accountLockService;
  }

  public void setAccountLockService(AccountLockService accountLockService) {
    this.accountLockService = accountLockService;
  }
}
