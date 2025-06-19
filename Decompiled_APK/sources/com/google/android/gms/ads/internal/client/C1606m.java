package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.widget.FrameLayout;
import com.google.android.gms.ads.nativead.NativeAdView;
import com.google.android.gms.dynamic.RemoteCreator$RemoteCreatorException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.A8;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.B8;
import com.google.android.gms.internal.ads.C1744Ob;
import com.google.android.gms.internal.ads.C8;
import com.google.android.gms.internal.ads.D8;
import com.google.android.gms.internal.ads.E8;
import com.google.android.gms.internal.ads.F8;
import com.google.android.gms.internal.ads.InterfaceC1750Pb;

/* renamed from: com.google.android.gms.ads.internal.client.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1606m extends AbstractC1612p {
    public final /* synthetic */ NativeAdView b;
    public final /* synthetic */ FrameLayout c;
    public final /* synthetic */ Context d;
    public final /* synthetic */ C1608n e;

    public C1606m(C1608n c1608n, NativeAdView nativeAdView, FrameLayout frameLayout, Context context) {
        this.b = nativeAdView;
        this.c = frameLayout;
        this.d = context;
        this.e = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.d, "native_ad_view_delegate");
        return new L0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.P1(new com.google.android.gms.dynamic.b(this.b), new com.google.android.gms.dynamic.b(this.c));
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object c() throws com.google.android.gms.ads.internal.util.client.zzr {
        IInterface d8;
        Context context = this.d;
        AbstractC2773w7.a(context);
        boolean zBooleanValue = ((Boolean) r.d.c.a(AbstractC2773w7.Ha)).booleanValue();
        FrameLayout frameLayout = this.c;
        NativeAdView nativeAdView = this.b;
        C1608n c1608n = this.e;
        if (!zBooleanValue) {
            G0 g0 = (G0) c1608n.d;
            try {
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
                com.google.android.gms.dynamic.b bVar2 = new com.google.android.gms.dynamic.b(nativeAdView);
                com.google.android.gms.dynamic.b bVar3 = new com.google.android.gms.dynamic.b(frameLayout);
                D8 d82 = (D8) ((F8) g0.k(context));
                Parcel parcelF3 = d82.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                AbstractC2857y5.e(parcelF3, bVar2);
                AbstractC2857y5.e(parcelF3, bVar3);
                parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY3 = d82.Y3(1, parcelF3);
                IBinder strongBinder = parcelY3.readStrongBinder();
                parcelY3.recycle();
                if (strongBinder == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegate");
                return iInterfaceQueryLocalInterface instanceof C8 ? (C8) iInterfaceQueryLocalInterface : new A8(strongBinder);
            } catch (RemoteException e) {
                e = e;
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote NativeAdViewDelegate.", e);
                return null;
            } catch (RemoteCreator$RemoteCreatorException e2) {
                e = e2;
                com.google.android.gms.ads.internal.util.client.i.i("Could not create remote NativeAdViewDelegate.", e);
                return null;
            }
        }
        try {
            com.google.android.gms.dynamic.b bVar4 = new com.google.android.gms.dynamic.b(context);
            com.google.android.gms.dynamic.b bVar5 = new com.google.android.gms.dynamic.b(nativeAdView);
            com.google.android.gms.dynamic.b bVar6 = new com.google.android.gms.dynamic.b(frameLayout);
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.ChimeraNativeAdViewDelegateCreatorImpl");
                int i = E8.a;
                if (iBinderB == null) {
                    d8 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface2 = iBinderB.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegateCreator");
                    d8 = iInterfaceQueryLocalInterface2 instanceof F8 ? (F8) iInterfaceQueryLocalInterface2 : new D8(iBinderB);
                }
                D8 d83 = (D8) d8;
                Parcel parcelF32 = d83.f3();
                AbstractC2857y5.e(parcelF32, bVar4);
                AbstractC2857y5.e(parcelF32, bVar5);
                AbstractC2857y5.e(parcelF32, bVar6);
                parcelF32.writeInt(ModuleDescriptor.MODULE_VERSION);
                Parcel parcelY32 = d83.Y3(1, parcelF32);
                IBinder strongBinder2 = parcelY32.readStrongBinder();
                parcelY32.recycle();
                int i2 = B8.a;
                if (strongBinder2 == null) {
                    return null;
                }
                IInterface iInterfaceQueryLocalInterface3 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegate");
                return iInterfaceQueryLocalInterface3 instanceof C8 ? (C8) iInterfaceQueryLocalInterface3 : new A8(strongBinder2);
            } catch (Exception e3) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e3);
            }
        } catch (RemoteException | com.google.android.gms.ads.internal.util.client.zzr | NullPointerException e4) {
            InterfaceC1750Pb interfaceC1750PbA = C1744Ob.a(context);
            c1608n.getClass();
            interfaceC1750PbA.d("ClientApiBroker.createNativeAdViewDelegate", e4);
            return null;
        }
    }
}
