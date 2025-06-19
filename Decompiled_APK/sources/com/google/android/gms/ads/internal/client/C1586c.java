package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.AdActivity;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.internal.ads.AbstractBinderC1666Bb;
import com.google.android.gms.internal.ads.AbstractBinderC1684Eb;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C1660Ab;
import com.google.android.gms.internal.ads.C1678Db;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.InterfaceC1672Cb;
import com.google.android.gms.internal.ads.InterfaceC1690Fb;
import com.google.android.gms.internal.ads.InterfaceC1750Pb;

/* renamed from: com.google.android.gms.ads.internal.client.c, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1586c extends AbstractC1612p {
    public final /* synthetic */ AdActivity b;
    public final /* synthetic */ C1608n c;

    public C1586c(C1608n c1608n, AdActivity adActivity) {
        this.b = adActivity;
        this.c = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object a() {
        C1608n.y(this.b, "ad_overlay");
        return null;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.D(new com.google.android.gms.dynamic.b(this.b));
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        IInterface c1678Db;
        AdActivity adActivity = this.b;
        AbstractC2773w7.a(adActivity);
        boolean zBooleanValue = ((Boolean) r.d.c.a(AbstractC2773w7.Ha)).booleanValue();
        C1608n c1608n = this.c;
        if (!zBooleanValue) {
            G0 g0 = (G0) c1608n.e;
            try {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(adActivity);
                C1678Db c1678Db2 = (C1678Db) ((InterfaceC1690Fb) g0.k(adActivity));
                Parcel parcelF3 = c1678Db2.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                Parcel parcelY3 = c1678Db2.Y3(1, parcelF3);
                IBinder strongBinder = parcelY3.readStrongBinder();
                parcelY3.recycle();
                if (strongBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.overlay.client.IAdOverlay");
                return iInterfaceQueryLocalInterface instanceof InterfaceC1672Cb ? (InterfaceC1672Cb) iInterfaceQueryLocalInterface : new C1660Ab(strongBinder);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote AdOverlay.", e);
                return null;
            } catch (RemoteCreator$RemoteCreatorException e2) {
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote AdOverlay.", e2);
                return null;
            }
        }
        try {
            com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(adActivity);
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(adActivity).b("com.google.android.gms.ads.ChimeraAdOverlayCreatorImpl");
                int i = AbstractBinderC1684Eb.a;
                if (iBinderB == null) {
                    c1678Db = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface2 = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.overlay.client.IAdOverlayCreator");
                    c1678Db = iInterfaceQueryLocalInterface2 instanceof InterfaceC1690Fb ? (InterfaceC1690Fb) iInterfaceQueryLocalInterface2 : new C1678Db(iBinderB);
                }
                C1678Db c1678Db3 = (C1678Db) c1678Db;
                Parcel parcelF32 = c1678Db3.f3();
                AbstractC2857y5.e(parcelF32, bVar2);
                Parcel parcelY32 = c1678Db3.Y3(1, parcelF32);
                IBinder strongBinder2 = parcelY32.readStrongBinder();
                parcelY32.recycle();
                int i2 = AbstractBinderC1666Bb.a;
                if (strongBinder2 == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.overlay.client.IAdOverlay");
                return iInterfaceQueryLocalInterface3 instanceof InterfaceC1672Cb ? (InterfaceC1672Cb) iInterfaceQueryLocalInterface3 : new C1660Ab(strongBinder2);
            } catch (Exception e3) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e3);
            }
        } catch (RemoteException | com.google.android.gms.ads.internal.util.client.zzr | NullPointerException e4) {
            InterfaceC1750Pb interfaceC1750PbA = C1744Ob.a(adActivity.getApplicationContext());
            c1608n.getClass();
            interfaceC1750PbA.d("ClientApiBroker.createAdOverlay", e4);
            return null;
        }
    }
}
