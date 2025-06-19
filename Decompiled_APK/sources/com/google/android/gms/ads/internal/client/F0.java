package com.google.android.gms.ads.internal.client;

import android.os.RemoteException;
import com.google.android.gms.internal.ads.InterfaceC2774w8;
import com.google.android.gms.internal.ads.J8;

/* loaded from: classes2.dex */
public final class F0 implements com.google.android.gms.ads.m {
    public final InterfaceC2774w8 a;
    public final com.google.android.gms.ads.s b = new com.google.android.gms.ads.s();
    public final J8 c;

    public F0(InterfaceC2774w8 interfaceC2774w8, J8 j8) {
        this.a = interfaceC2774w8;
        this.c = j8;
    }

    public final com.google.android.gms.ads.s a() {
        com.google.android.gms.ads.s sVar = this.b;
        try {
            InterfaceC2774w8 interfaceC2774w8 = this.a;
            if (interfaceC2774w8.g() != null) {
                sVar.b(interfaceC2774w8.g());
                return sVar;
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Exception occurred while getting video controller", e);
        }
        return sVar;
    }

    public final boolean b() {
        try {
            return this.a.k();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return false;
        }
    }
}
