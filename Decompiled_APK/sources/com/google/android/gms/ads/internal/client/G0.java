package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1678Db;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.D8;
import com.google.android.gms.internal.ads.F8;
import com.google.android.gms.internal.ads.InterfaceC1690Fb;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public final class G0 extends androidx.appcompat.app.y {
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ G0(String str, int i) {
        super(str, 5);
        this.d = i;
    }

    @Override // androidx.appcompat.app.y
    public final /* synthetic */ Object j(IBinder iBinder) {
        switch (this.d) {
            case 0:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IMobileAdsSettingManagerCreator");
                return iInterfaceQueryLocalInterface instanceof C1587c0 ? (C1587c0) iInterfaceQueryLocalInterface : new C1587c0(iBinder);
            case 1:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface2 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoaderBuilderCreator");
                return iInterfaceQueryLocalInterface2 instanceof H ? (H) iInterfaceQueryLocalInterface2 : new H(iBinder);
            case 2:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManagerCreator");
                return iInterfaceQueryLocalInterface3 instanceof L ? (L) iInterfaceQueryLocalInterface3 : new L(iBinder);
            case 3:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface4 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegateCreator");
                return iInterfaceQueryLocalInterface4 instanceof F8 ? (F8) iInterfaceQueryLocalInterface4 : new D8(iBinder);
            default:
                if (iBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface5 = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.overlay.client.IAdOverlayCreator");
                return iInterfaceQueryLocalInterface5 instanceof InterfaceC1690Fb ? (InterfaceC1690Fb) iInterfaceQueryLocalInterface5 : new C1678Db(iBinder);
        }
    }

    public K v(Context context, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) throws com.google.android.gms.ads.internal.util.client.zzr {
        L l;
        zzr zzrVar2;
        String str2;
        InterfaceC2825xa interfaceC2825xa2;
        int i2;
        AbstractC2773w7.a(context);
        if (((Boolean) r.d.c.a(AbstractC2773w7.Ha)).booleanValue()) {
            try {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
                try {
                    IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.ChimeraAdManagerCreatorImpl");
                    if (iBinderB == null) {
                        zzrVar2 = zzrVar;
                        str2 = str;
                        interfaceC2825xa2 = interfaceC2825xa;
                        i2 = i;
                        l = null;
                    } else {
                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManagerCreator");
                        l = iInterfaceQueryLocalInterface instanceof L ? (L) iInterfaceQueryLocalInterface : new L(iBinderB);
                        zzrVar2 = zzrVar;
                        str2 = str;
                        interfaceC2825xa2 = interfaceC2825xa;
                        i2 = i;
                    }
                    IBinder iBinderH4 = l.h4(bVar, zzrVar2, str2, interfaceC2825xa2, i2);
                    if (iBinderH4 != null) {
                        IInterface iInterfaceQueryLocalInterface2 = iBinderH4.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
                        return iInterfaceQueryLocalInterface2 instanceof K ? (K) iInterfaceQueryLocalInterface2 : new I(iBinderH4);
                    }
                } catch (Exception e) {
                    throw new com.google.android.gms.ads.internal.util.client.zzr(e);
                }
            } catch (RemoteException e2) {
                e = e2;
                Exception exc = e;
                C1744Ob.a(context).d("AdManagerCreator.newAdManagerByDynamiteLoader", exc);
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", exc);
                return null;
            } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
                e = e3;
                Exception exc2 = e;
                C1744Ob.a(context).d("AdManagerCreator.newAdManagerByDynamiteLoader", exc2);
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", exc2);
                return null;
            } catch (NullPointerException e4) {
                e = e4;
                Exception exc22 = e;
                C1744Ob.a(context).d("AdManagerCreator.newAdManagerByDynamiteLoader", exc22);
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", exc22);
                return null;
            }
        } else {
            try {
                IBinder iBinderH42 = ((L) k(context)).h4(new com.google.android.gms.dynamic.b(context), zzrVar, str, interfaceC2825xa, i);
                if (iBinderH42 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = iBinderH42.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
                    return iInterfaceQueryLocalInterface3 instanceof K ? (K) iInterfaceQueryLocalInterface3 : new I(iBinderH42);
                }
            } catch (RemoteException | RemoteCreator$RemoteCreatorException unused) {
                com.google.android.gms.ads.internal.util.client.i.k(3);
            }
        }
        return null;
    }
}
