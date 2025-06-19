package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.admanager.AdManagerAdView;

/* renamed from: com.google.android.gms.internal.ads.b9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1869b9 extends AbstractBinderC2814x5 implements S8 {
    public final com.google.android.gms.ads.formats.c a;

    public BinderC1869b9(com.google.android.gms.ads.formats.c cVar) {
        super("com.google.android.gms.ads.internal.formats.client.IOnPublisherAdViewLoadedListener");
        this.a = cVar;
    }

    @Override // com.google.android.gms.internal.ads.S8
    public final void H0(com.google.android.gms.ads.internal.client.K k, com.google.android.gms.dynamic.a aVar) {
        if (k == null || aVar == null) {
            return;
        }
        AdManagerAdView adManagerAdView = new AdManagerAdView((Context) com.google.android.gms.dynamic.b.I3(aVar));
        try {
            if (k.zzi() instanceof com.google.android.gms.ads.internal.client.O0) {
                com.google.android.gms.ads.internal.client.O0 o0 = (com.google.android.gms.ads.internal.client.O0) k.zzi();
                adManagerAdView.setAdListener(o0 != null ? o0.a : null);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
        try {
            if (k.i() instanceof I5) {
                I5 i5 = (I5) k.i();
                adManagerAdView.setAppEventListener(i5 != null ? i5.a : null);
            }
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.f("", e2);
        }
        com.google.android.gms.ads.internal.util.client.c.b.post(new C(3, this, adManagerAdView, k, false));
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        com.google.android.gms.ads.internal.client.K i2;
        if (i != 1) {
            return false;
        }
        IBinder strongBinder = parcel.readStrongBinder();
        if (strongBinder == null) {
            i2 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
            i2 = iInterfaceQueryLocalInterface instanceof com.google.android.gms.ads.internal.client.K ? (com.google.android.gms.ads.internal.client.K) iInterfaceQueryLocalInterface : new com.google.android.gms.ads.internal.client.I(strongBinder);
        }
        com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
        AbstractC2857y5.b(parcel);
        H0(i2, aVarV3);
        parcel2.writeNoException();
        return true;
    }
}
