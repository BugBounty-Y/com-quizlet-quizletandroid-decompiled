package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.BinderC2739va;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.InterfaceC1750Pb;

/* renamed from: com.google.android.gms.ads.internal.client.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1602k extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ String c;
    public final /* synthetic */ BinderC2739va d;
    public final /* synthetic */ C1608n e;

    public C1602k(C1608n c1608n, Context context, String str, BinderC2739va binderC2739va) {
        this.b = context;
        this.c = str;
        this.d = binderC2739va;
        this.e = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, "native_ad");
        return new I0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.b1(new com.google.android.gms.dynamic.b(this.b), this.c, this.d, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        H h;
        Context context = this.b;
        AbstractC2773w7.a(context);
        boolean zBooleanValue = ((Boolean) r.d.c.a(AbstractC2773w7.Ha)).booleanValue();
        BinderC2739va binderC2739va = this.d;
        C1608n c1608n = this.e;
        String str = this.c;
        if (!zBooleanValue) {
            G0 g0 = (G0) c1608n.b;
            try {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
                H h2 = (H) g0.k(context);
                Parcel parcelF3 = h2.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                parcelF3.writeString(str);
                AbstractC2857y5.e(parcelF3, binderC2739va);
                parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY3 = h2.Y3(1, parcelF3);
                IBinder strongBinder = parcelY3.readStrongBinder();
                parcelY3.recycle();
                if (strongBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoaderBuilder");
                return iInterfaceQueryLocalInterface instanceof G ? (G) iInterfaceQueryLocalInterface : new E(strongBinder);
            } catch (RemoteException e) {
                e = e;
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote builder for AdLoader.", e);
                return null;
            } catch (RemoteCreator$RemoteCreatorException e2) {
                e = e2;
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote builder for AdLoader.", e);
                return null;
            }
        }
        try {
            com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(context);
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.ChimeraAdLoaderBuilderCreatorImpl");
                if (iBinderB == null) {
                    h = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface2 = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoaderBuilderCreator");
                    h = iInterfaceQueryLocalInterface2 instanceof H ? (H) iInterfaceQueryLocalInterface2 : new H(iBinderB);
                }
                Parcel parcelF32 = h.f3();
                AbstractC2857y5.e(parcelF32, bVar2);
                parcelF32.writeString(str);
                AbstractC2857y5.e(parcelF32, binderC2739va);
                parcelF32.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY32 = h.Y3(1, parcelF32);
                IBinder strongBinder2 = parcelY32.readStrongBinder();
                parcelY32.recycle();
                if (strongBinder2 == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoaderBuilder");
                return iInterfaceQueryLocalInterface3 instanceof G ? (G) iInterfaceQueryLocalInterface3 : new E(strongBinder2);
            } catch (Exception e3) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e3);
            }
        } catch (RemoteException e4) {
            e = e4;
            InterfaceC1750Pb interfaceC1750PbA = C1744Ob.a(context);
            c1608n.getClass();
            interfaceC1750PbA.d("ClientApiBroker.createAdLoaderBuilder", e);
            return null;
        } catch (com.google.android.gms.ads.internal.util.client.zzr e5) {
            e = e5;
            InterfaceC1750Pb interfaceC1750PbA2 = C1744Ob.a(context);
            c1608n.getClass();
            interfaceC1750PbA2.d("ClientApiBroker.createAdLoaderBuilder", e);
            return null;
        } catch (NullPointerException e6) {
            e = e6;
            InterfaceC1750Pb interfaceC1750PbA22 = C1744Ob.a(context);
            c1608n.getClass();
            interfaceC1750PbA22.d("ClientApiBroker.createAdLoaderBuilder", e);
            return null;
        }
    }
}
