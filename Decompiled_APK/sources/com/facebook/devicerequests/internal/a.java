package com.facebook.devicerequests.internal;

import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements NsdManager.RegistrationListener {
    public final /* synthetic */ String a;
    public final /* synthetic */ String b;

    public a(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    @Override // android.net.nsd.NsdManager.RegistrationListener
    public final void onRegistrationFailed(NsdServiceInfo serviceInfo, int i) {
        Intrinsics.checkNotNullParameter(serviceInfo, "serviceInfo");
        b.a(this.b);
    }

    @Override // android.net.nsd.NsdManager.RegistrationListener
    public final void onServiceRegistered(NsdServiceInfo NsdServiceInfo) {
        Intrinsics.checkNotNullParameter(NsdServiceInfo, "NsdServiceInfo");
        if (Intrinsics.b(this.a, NsdServiceInfo.getServiceName())) {
            return;
        }
        b.a(this.b);
    }

    @Override // android.net.nsd.NsdManager.RegistrationListener
    public final void onServiceUnregistered(NsdServiceInfo serviceInfo) {
        Intrinsics.checkNotNullParameter(serviceInfo, "serviceInfo");
    }

    @Override // android.net.nsd.NsdManager.RegistrationListener
    public final void onUnregistrationFailed(NsdServiceInfo serviceInfo, int i) {
        Intrinsics.checkNotNullParameter(serviceInfo, "serviceInfo");
    }
}
