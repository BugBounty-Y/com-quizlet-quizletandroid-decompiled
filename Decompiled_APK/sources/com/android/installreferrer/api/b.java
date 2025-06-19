package com.android.installreferrer.api;

import android.content.ComponentName;
import android.content.ServiceConnection;
import android.os.IBinder;
import android.os.IInterface;
import com.android.installreferrer.commons.InstallReferrerCommons;
import com.google.android.finsky.externalreferrer.c;

/* loaded from: classes.dex */
public final class b implements ServiceConnection {
    public final InstallReferrerStateListener a;
    public final /* synthetic */ InstallReferrerClientImpl b;

    public b(InstallReferrerClientImpl installReferrerClientImpl, InstallReferrerStateListener installReferrerStateListener) {
        this.b = installReferrerClientImpl;
        if (installReferrerStateListener == null) {
            throw new RuntimeException("Please specify a listener to know when setup is done.");
        }
        this.a = installReferrerStateListener;
    }

    @Override // android.content.ServiceConnection
    public final void onServiceConnected(ComponentName componentName, IBinder iBinder) {
        c aVar;
        InstallReferrerCommons.logVerbose("InstallReferrerClient", "Install Referrer service connected.");
        int i = com.google.android.finsky.externalreferrer.b.a;
        if (iBinder == null) {
            aVar = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.finsky.externalreferrer.IGetInstallReferrerService");
            aVar = iInterfaceQueryLocalInterface instanceof c ? (c) iInterfaceQueryLocalInterface : new com.google.android.finsky.externalreferrer.a(iBinder);
        }
        InstallReferrerClientImpl installReferrerClientImpl = this.b;
        installReferrerClientImpl.c = aVar;
        installReferrerClientImpl.a = 2;
        this.a.onInstallReferrerSetupFinished(0);
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        InstallReferrerCommons.logWarn("InstallReferrerClient", "Install Referrer service disconnected.");
        InstallReferrerClientImpl installReferrerClientImpl = this.b;
        installReferrerClientImpl.c = null;
        installReferrerClientImpl.a = 0;
        this.a.onInstallReferrerServiceDisconnected();
    }
}
