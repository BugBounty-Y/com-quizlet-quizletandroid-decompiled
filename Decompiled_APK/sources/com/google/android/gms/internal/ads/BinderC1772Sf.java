package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.InterfaceC1609n0;

/* renamed from: com.google.android.gms.internal.ads.Sf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1772Sf extends AbstractBinderC2814x5 implements Y5 {
    public final C1766Rf a;
    public final com.google.android.gms.ads.internal.client.K b;
    public final C2411np c;
    public boolean d;
    public final Hk e;

    public BinderC1772Sf(C1766Rf c1766Rf, com.google.android.gms.ads.internal.client.K k, C2411np c2411np, Hk hk) {
        super("com.google.android.gms.ads.internal.appopen.client.IAppOpenAd");
        this.d = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.M0)).booleanValue();
        this.a = c1766Rf;
        this.b = k;
        this.c = c2411np;
        this.e = hk;
    }

    @Override // com.google.android.gms.internal.ads.Y5
    public final void X0(com.google.android.gms.dynamic.a aVar, InterfaceC1953d6 interfaceC1953d6) {
        try {
            this.c.d.set(interfaceC1953d6);
            this.a.c((Activity) com.google.android.gms.dynamic.b.I3(aVar), this.d);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC1953d6 c1909c6 = null;
        String strW = null;
        com.google.android.gms.ads.internal.client.K k = this.b;
        switch (i) {
            case 2:
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, k);
                return true;
            case 3:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.appopen.client.IAppOpenAdPresentationCallback");
                }
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                return true;
            case 4:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.appopen.client.IAppOpenFullScreenContentCallback");
                    c1909c6 = iInterfaceQueryLocalInterface instanceof InterfaceC1953d6 ? (InterfaceC1953d6) iInterfaceQueryLocalInterface : new C1909c6(strongBinder2, "com.google.android.gms.ads.internal.appopen.client.IAppOpenFullScreenContentCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                X0(aVarV3, c1909c6);
                parcel2.writeNoException();
                return true;
            case 5:
                com.google.android.gms.ads.internal.client.s0 s0VarF = f();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, s0VarF);
                return true;
            case 6:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                this.d = zF;
                parcel2.writeNoException();
                return true;
            case 7:
                InterfaceC1609n0 interfaceC1609n0E4 = com.google.android.gms.ads.internal.client.N0.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                com.google.android.gms.common.internal.u.d("setOnPaidEventListener must be called on the main UI thread.");
                C2411np c2411np = this.c;
                if (c2411np != null) {
                    try {
                        if (!interfaceC1609n0E4.f()) {
                            this.e.b();
                        }
                    } catch (RemoteException unused) {
                        com.google.android.gms.ads.internal.util.client.i.k(3);
                    }
                    c2411np.g.set(interfaceC1609n0E4);
                }
                parcel2.writeNoException();
                return true;
            case 8:
                try {
                    strW = k.w();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                }
                parcel2.writeNoException();
                parcel2.writeString(strW);
                return true;
            default:
                return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.Y5
    public final com.google.android.gms.ads.internal.client.s0 f() {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H6)).booleanValue()) {
            return this.a.f;
        }
        return null;
    }
}
