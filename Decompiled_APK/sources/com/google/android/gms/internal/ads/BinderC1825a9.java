package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import androidx.compose.ui.platform.C0960p;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.ads.a9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1825a9 extends AbstractBinderC2814x5 implements P8 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BinderC1825a9(Object obj, int i) {
        super("com.google.android.gms.ads.internal.formats.client.IOnCustomTemplateAdLoadedListener");
        this.a = i;
        this.b = obj;
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
        AbstractC2857y5.b(parcel);
        l3(i8);
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.P8
    public final void l3(J8 j8) {
        Os os;
        String strZzi;
        C2654tb it2;
        switch (this.a) {
            case 0:
                C2326lq c2326lq = (C2326lq) this.b;
                com.google.ads.mediation.d dVar = (com.google.ads.mediation.d) c2326lq.b;
                synchronized (c2326lq) {
                    os = (Os) c2326lq.d;
                    if (os == null) {
                        os = new Os(j8);
                        c2326lq.d = os;
                    }
                }
                C2326lq c2326lq2 = (C2326lq) ((com.google.android.gms.ads.mediation.l) dVar.d);
                c2326lq2.getClass();
                com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
                try {
                    strZzi = ((J8) os.b).zzi();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("", e);
                    strZzi = null;
                }
                com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdLoaded with template id ".concat(String.valueOf(strZzi)));
                c2326lq2.d = os;
                try {
                    ((InterfaceC1671Ca) c2326lq2.b).v();
                    return;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                    return;
                }
            default:
                C1732Mb c1732Mb = (C1732Mb) this.b;
                com.google.firebase.tracing.a aVar = (com.google.firebase.tracing.a) c1732Mb.b;
                synchronized (c1732Mb) {
                    it2 = (C2654tb) c1732Mb.c;
                    if (it2 == null) {
                        it2 = new C2654tb(j8);
                        c1732Mb.c = it2;
                    }
                }
                Intrinsics.checkNotNullParameter(it2, "it");
                ((C0960p) aVar.b).invoke(it2, (com.quizlet.ads.data.d) aVar.c);
                return;
        }
    }
}
