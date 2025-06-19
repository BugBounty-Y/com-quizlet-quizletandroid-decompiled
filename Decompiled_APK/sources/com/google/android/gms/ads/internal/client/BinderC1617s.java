package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C2326lq;
import com.google.android.gms.internal.ads.InterfaceC1671Ca;

/* renamed from: com.google.android.gms.ads.internal.client.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1617s extends AbstractBinderC2814x5 implements V {
    public final com.google.android.gms.internal.instantapps.a a;

    public BinderC1617s(com.google.android.gms.internal.instantapps.a aVar) {
        super("com.google.android.gms.ads.internal.client.IFullScreenContentCallback");
        this.a = aVar;
    }

    @Override // com.google.android.gms.ads.internal.client.V
    public final void S(zze zzeVar) {
        if (this.a != null) {
            zzeVar.a();
        }
    }

    @Override // com.google.android.gms.ads.internal.client.V
    public final void b() {
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        if (i == 1) {
            zze zzeVar = (zze) AbstractC2857y5.a(parcel, zze.CREATOR);
            AbstractC2857y5.b(parcel);
            S(zzeVar);
        } else if (i == 2) {
            f();
        } else if (i == 3) {
            q();
        } else if (i != 4 && i != 5) {
            return false;
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.ads.internal.client.V
    public final void f() {
        com.google.android.gms.internal.instantapps.a aVar = this.a;
        if (aVar != null) {
            C2326lq c2326lq = (C2326lq) ((com.google.android.gms.ads.mediation.j) aVar.b);
            c2326lq.getClass();
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdOpened.");
            try {
                ((InterfaceC1671Ca) c2326lq.b).o();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.V
    public final void q() {
        com.google.android.gms.internal.instantapps.a aVar = this.a;
        if (aVar != null) {
            C2326lq c2326lq = (C2326lq) ((com.google.android.gms.ads.mediation.j) aVar.b);
            c2326lq.getClass();
            com.google.android.gms.common.internal.u.d("#008 Must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.i.d("Adapter called onAdClosed.");
            try {
                ((InterfaceC1671Ca) c2326lq.b).f();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.client.V
    public final void zze() {
    }
}
