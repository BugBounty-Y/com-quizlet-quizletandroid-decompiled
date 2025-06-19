package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final /* synthetic */ class Qn implements InterfaceC1840ah {
    public final /* synthetic */ Ln a;
    public final /* synthetic */ P9 b;

    public /* synthetic */ Qn(Ln ln, P9 p9) {
        this.a = ln;
        this.b = p9;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        this.a.m0(zzeVar);
        P9 p9 = this.b;
        if (p9 != null) {
            try {
                Parcel parcelF3 = p9.f3();
                AbstractC2857y5.c(parcelF3, zzeVar);
                p9.d4(3, parcelF3);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
            }
        }
        if (p9 != null) {
            try {
                int i = zzeVar.a;
                Parcel parcelF32 = p9.f3();
                parcelF32.writeInt(i);
                p9.d4(2, parcelF32);
            } catch (RemoteException e2) {
                com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
            }
        }
    }
}
