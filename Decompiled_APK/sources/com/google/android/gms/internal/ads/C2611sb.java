package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1597h0;
import com.google.android.gms.ads.internal.client.InterfaceC1595g0;
import com.google.android.gms.ads.nativead.NativeAd;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.sb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2611sb extends NativeAd {
    public final Y8 a;
    public final ArrayList b = new ArrayList();
    public final ArrayList c = new ArrayList();

    public C2611sb(Y8 y8) {
        this.a = y8;
        try {
            List listC = y8.c();
            if (listC != null) {
                for (Object obj : listC) {
                    InterfaceC2860y8 interfaceC2860y8E4 = obj instanceof IBinder ? BinderC2474p8.e4((IBinder) obj) : null;
                    if (interfaceC2860y8E4 != null) {
                        this.b.add(new C2568rb(interfaceC2860y8E4));
                    }
                }
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
        try {
            List listD = this.a.d();
            if (listD != null) {
                for (Object obj2 : listD) {
                    InterfaceC1595g0 interfaceC1595g0E4 = obj2 instanceof IBinder ? com.google.android.gms.ads.internal.client.E0.e4((IBinder) obj2) : null;
                    if (interfaceC1595g0E4 != null) {
                        this.c.add(new C1597h0(interfaceC1595g0E4));
                    }
                }
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        try {
            InterfaceC2860y8 interfaceC2860y8N = this.a.n();
            if (interfaceC2860y8N != null) {
                new C2568rb(interfaceC2860y8N);
            }
        } catch (RemoteException e3) {
            com.google.android.gms.ads.internal.util.client.i.f("", e3);
        }
        try {
            if (this.a.zzi() != null) {
                new C2688u8(this.a.zzi(), 1);
            }
        } catch (RemoteException e4) {
            com.google.android.gms.ads.internal.util.client.i.f("", e4);
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeAd
    public final String a() {
        try {
            return this.a.x();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeAd
    public final String b() {
        try {
            return this.a.p();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeAd
    public final com.google.android.gms.ads.q c() {
        com.google.android.gms.ads.internal.client.s0 s0VarH;
        try {
            s0VarH = this.a.h();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            s0VarH = null;
        }
        if (s0VarH != null) {
            return new com.google.android.gms.ads.q(s0VarH);
        }
        return null;
    }

    @Override // com.google.android.gms.ads.nativead.NativeAd
    public final /* bridge */ /* synthetic */ com.google.android.gms.dynamic.a d() {
        try {
            return this.a.l();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            return null;
        }
    }

    @Override // com.google.android.gms.ads.nativead.NativeAd
    public final void recordEvent(Bundle bundle) {
        try {
            this.a.I1(bundle);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Failed to record native event", e);
        }
    }
}
