package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public final class Z8 extends AbstractBinderC2814x5 implements N8 {
    public final /* synthetic */ C2326lq a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Z8(C2326lq c2326lq) {
        super("com.google.android.gms.ads.internal.formats.client.IOnCustomClickListener");
        this.a = c2326lq;
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        J8 i8;
        if (i != 1) {
            return false;
        }
        IBinder strongBinder = parcel.readStrongBinder();
        if (strongBinder == null) {
            i8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeCustomTemplateAd");
            i8 = iInterfaceQueryLocalInterface instanceof J8 ? (J8) iInterfaceQueryLocalInterface : new I8(strongBinder);
        }
        String string = parcel.readString();
        AbstractC2857y5.b(parcel);
        e3(i8, string);
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.N8
    public final void e3(J8 j8, String str) {
        Os os;
        C2326lq c2326lq = this.a;
        com.google.ads.mediation.d dVar = (com.google.ads.mediation.d) c2326lq.c;
        if (dVar == null) {
            return;
        }
        synchronized (c2326lq) {
            os = (Os) c2326lq.d;
            if (os == null) {
                os = new Os(j8);
                c2326lq.d = os;
            }
        }
        C2326lq c2326lq2 = (C2326lq) ((com.google.android.gms.ads.mediation.l) dVar.d);
        c2326lq2.getClass();
        try {
            ((InterfaceC1671Ca) c2326lq2.b).w1((J8) os.b, str);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }
}
