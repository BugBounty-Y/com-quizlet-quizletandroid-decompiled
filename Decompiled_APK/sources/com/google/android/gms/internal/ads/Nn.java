package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.InterfaceC1619u;

/* loaded from: classes2.dex */
public final class Nn implements InterfaceC1582a, InterfaceC2447oi {
    public InterfaceC1619u a;

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final synchronized void c() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2447oi
    public final synchronized void c0() {
        InterfaceC1619u interfaceC1619u = this.a;
        if (interfaceC1619u != null) {
            try {
                interfaceC1619u.b();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Remote Exception at onPhysicalClick.", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final synchronized void onAdClicked() {
        InterfaceC1619u interfaceC1619u = this.a;
        if (interfaceC1619u != null) {
            try {
                interfaceC1619u.b();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Remote Exception at onAdClicked.", e);
            }
        }
    }
}
