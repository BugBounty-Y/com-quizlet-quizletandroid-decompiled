package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.ads.mediation.AbstractAdViewAdapter;
import com.google.ads.mediation.admob.AdMobAdapter;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.c9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1912c9 extends AbstractBinderC2814x5 implements U8 {
    public final /* synthetic */ int a;
    public final Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC1912c9(Object obj, int i) {
        super("com.google.android.gms.ads.internal.formats.client.IOnUnifiedNativeAdLoadedListener");
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.U8
    public final void W0(Y8 y8) throws SecurityException {
        String strP;
        String strX;
        String strO;
        String strM;
        String strS;
        String strZ;
        double dZze;
        switch (this.a) {
            case 0:
                com.quizlet.data.repository.folderwithcreatorinclass.e eVar = new com.quizlet.data.repository.folderwithcreatorinclass.e(y8);
                com.google.ads.mediation.d dVar = (com.google.ads.mediation.d) this.b;
                dVar.getClass();
                com.google.ads.mediation.a aVar = new com.google.ads.mediation.a();
                aVar.l = new Bundle();
                Y8 y82 = (Y8) eVar.a;
                Object objI3 = null;
                try {
                    strP = y82.p();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                    strP = null;
                }
                aVar.a = strP;
                aVar.b = (ArrayList) eVar.b;
                try {
                    strX = y82.x();
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e2);
                    strX = null;
                }
                aVar.c = strX;
                aVar.d = (C2903z8) eVar.c;
                try {
                    strO = y82.o();
                } catch (RemoteException e3) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e3);
                    strO = null;
                }
                aVar.e = strO;
                try {
                    strM = y82.m();
                } catch (RemoteException e4) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e4);
                    strM = null;
                }
                aVar.f = strM;
                try {
                    dZze = y82.zze();
                } catch (RemoteException e5) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e5);
                }
                Double dValueOf = dZze == -1.0d ? null : Double.valueOf(dZze);
                aVar.g = dValueOf;
                try {
                    strS = y82.s();
                } catch (RemoteException e6) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e6);
                    strS = null;
                }
                aVar.h = strS;
                try {
                    strZ = y82.z();
                } catch (RemoteException e7) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e7);
                    strZ = null;
                }
                aVar.i = strZ;
                try {
                    com.google.android.gms.dynamic.a aVarK = y82.k();
                    if (aVarK != null) {
                        objI3 = com.google.android.gms.dynamic.b.I3(aVarK);
                    }
                } catch (RemoteException e8) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e8);
                }
                aVar.k = objI3;
                aVar.m = true;
                aVar.n = true;
                com.google.android.gms.ads.s sVar = (com.google.android.gms.ads.s) eVar.d;
                try {
                    if (y82.g() != null) {
                        sVar.b(y82.g());
                    }
                } catch (RemoteException e9) {
                    com.google.android.gms.ads.internal.util.client.i.f("Exception occurred while getting video controller", e9);
                }
                aVar.j = sVar;
                C2326lq c2326lq = (C2326lq) ((com.google.android.gms.ads.mediation.l) dVar.d);
                c2326lq.getClass();
                com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
                com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdLoaded.");
                c2326lq.c = aVar;
                if (!(((AbstractAdViewAdapter) dVar.c) instanceof AdMobAdapter)) {
                    Object obj = new Object();
                    new BinderC1713Ja();
                    synchronized (obj) {
                    }
                }
                try {
                    ((InterfaceC1671Ca) c2326lq.b).v();
                    return;
                } catch (RemoteException e10) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e10);
                    return;
                }
            default:
                C2611sb c2611sb = new C2611sb(y8);
                C2326lq c2326lq2 = (C2326lq) this.b;
                ((BinderC2707ul) c2326lq2.b).e4((String) c2326lq2.c, (String) c2326lq2.d, c2611sb);
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        Y8 w8;
        if (i != 1) {
            return false;
        }
        IBinder strongBinder = parcel.readStrongBinder();
        if (strongBinder == null) {
            w8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IUnifiedNativeAd");
            w8 = iInterfaceQueryLocalInterface instanceof Y8 ? (Y8) iInterfaceQueryLocalInterface : new W8(strongBinder, "com.google.android.gms.ads.internal.formats.client.IUnifiedNativeAd", 0);
        }
        AbstractC2857y5.b(parcel);
        W0(w8);
        parcel2.writeNoException();
        return true;
    }
}
