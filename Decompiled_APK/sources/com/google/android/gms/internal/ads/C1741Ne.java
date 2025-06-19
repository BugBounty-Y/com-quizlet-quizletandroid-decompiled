package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;

/* renamed from: com.google.android.gms.internal.ads.Ne, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1741Ne implements CC {
    public final /* synthetic */ int a;
    public final C1723Ke b;

    public /* synthetic */ C1741Ne(C1723Ke c1723Ke, int i) {
        this.a = i;
        this.b = c1723Ke;
    }

    public Context a() {
        Context context = this.b.b;
        AbstractC1981ds.s(context);
        return context;
    }

    public VersionInfoParcel b() {
        VersionInfoParcel versionInfoParcel = this.b.a;
        AbstractC1981ds.s(versionInfoParcel);
        return versionInfoParcel;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                Context context = this.b.b;
                AbstractC1981ds.s(context);
                return context;
            case 1:
                WeakReference weakReference = this.b.d;
                AbstractC1981ds.s(weakReference);
                return weakReference;
            case 2:
                return new C2302l8(this.b.b);
            case 3:
                C1723Ke c1723Ke = this.b;
                return new com.google.android.gms.ads.internal.e(c1723Ke.b, c1723Ke.a);
            case 4:
                C1723Ke c1723Ke2 = this.b;
                String strY = com.google.android.gms.ads.internal.j.C.c.y(c1723Ke2.b, c1723Ke2.a.a);
                AbstractC1981ds.s(strY);
                return strY;
            case 5:
                VersionInfoParcel versionInfoParcel = this.b.a;
                AbstractC1981ds.s(versionInfoParcel);
                return versionInfoParcel;
            default:
                return Long.valueOf(this.b.c);
        }
    }
}
