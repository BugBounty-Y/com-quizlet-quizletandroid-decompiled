package com.google.android.gms.ads.internal.client;

import android.app.Activity;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.InterfaceC1750Pb;

/* renamed from: com.google.android.gms.ads.internal.client.l, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1604l extends AbstractC1612p {
    public final /* synthetic */ Activity b;
    public final /* synthetic */ C1608n c;

    public C1604l(C1608n c1608n, Activity activity) {
        this.b = activity;
        this.c = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, "mobile_ads_settings");
        return new K0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.V2(new com.google.android.gms.dynamic.b(this.b), ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        C1587c0 c1587c0;
        Activity activity = this.b;
        AbstractC2773w7.a(activity);
        boolean zBooleanValue = ((Boolean) r.d.c.a(AbstractC2773w7.Ha)).booleanValue();
        C1608n c1608n = this.c;
        if (!zBooleanValue) {
            G0 g0 = (G0) c1608n.c;
            try {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(activity);
                C1587c0 c1587c02 = (C1587c0) g0.k(activity);
                Parcel parcelF3 = c1587c02.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY3 = c1587c02.Y3(1, parcelF3);
                IBinder strongBinder = parcelY3.readStrongBinder();
                parcelY3.recycle();
                if (strongBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IMobileAdsSettingManager");
                return iInterfaceQueryLocalInterface instanceof InterfaceC1585b0 ? (InterfaceC1585b0) iInterfaceQueryLocalInterface : new Z(strongBinder);
            } catch (RemoteException e) {
                e = e;
                com.google.android.gms.ads.internal.util.client.i.i("Could not get remote MobileAdsSettingManager.", e);
                return null;
            } catch (RemoteCreator$RemoteCreatorException e2) {
                e = e2;
                com.google.android.gms.ads.internal.util.client.i.i("Could not get remote MobileAdsSettingManager.", e);
                return null;
            }
        }
        try {
            com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(activity);
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(activity).b("com.google.android.gms.ads.ChimeraMobileAdsSettingManagerCreatorImpl");
                if (iBinderB == null) {
                    c1587c0 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface2 = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.client.IMobileAdsSettingManagerCreator");
                    c1587c0 = iInterfaceQueryLocalInterface2 instanceof C1587c0 ? (C1587c0) iInterfaceQueryLocalInterface2 : new C1587c0(iBinderB);
                }
                Parcel parcelF32 = c1587c0.f3();
                AbstractC2857y5.e(parcelF32, bVar2);
                parcelF32.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY32 = c1587c0.Y3(1, parcelF32);
                IBinder strongBinder2 = parcelY32.readStrongBinder();
                parcelY32.recycle();
                if (strongBinder2 == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.client.IMobileAdsSettingManager");
                return iInterfaceQueryLocalInterface3 instanceof InterfaceC1585b0 ? (InterfaceC1585b0) iInterfaceQueryLocalInterface3 : new Z(strongBinder2);
            } catch (Exception e3) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e3);
            }
        } catch (RemoteException e4) {
            e = e4;
            InterfaceC1750Pb interfaceC1750PbA = C1744Ob.a(activity);
            c1608n.getClass();
            interfaceC1750PbA.d("ClientApiBroker.getMobileAdsSettingsManager", e);
            return null;
        } catch (com.google.android.gms.ads.internal.util.client.zzr e5) {
            e = e5;
            InterfaceC1750Pb interfaceC1750PbA2 = C1744Ob.a(activity);
            c1608n.getClass();
            interfaceC1750PbA2.d("ClientApiBroker.getMobileAdsSettingsManager", e);
            return null;
        } catch (NullPointerException e6) {
            e = e6;
            InterfaceC1750Pb interfaceC1750PbA22 = C1744Ob.a(activity);
            c1608n.getClass();
            interfaceC1750PbA22.d("ClientApiBroker.getMobileAdsSettingsManager", e);
            return null;
        }
    }
}
