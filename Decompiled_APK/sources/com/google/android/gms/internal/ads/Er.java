package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.ClientApi;
import com.google.android.gms.ads.internal.client.zzfp;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Er {
    public final Context a;
    public final VersionInfoParcel b;
    public final ScheduledExecutorService c;
    public final ClientApi d = new ClientApi();
    public InterfaceC2825xa e;
    public final com.google.android.gms.common.util.a f;

    public Er(Context context, VersionInfoParcel versionInfoParcel, ScheduledExecutorService scheduledExecutorService, com.google.android.gms.common.util.a aVar) {
        this.a = context;
        this.b = versionInfoParcel;
        this.c = scheduledExecutorService;
        this.f = aVar;
    }

    public static C2713ur b() {
        C2601s7 c2601s7 = AbstractC2773w7.z;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        return new C2713ur(((Long) rVar.c.a(c2601s7)).longValue(), ((Long) rVar.c.a(AbstractC2773w7.A)).longValue());
    }

    public final C2670tr a(zzfp zzfpVar, com.google.android.gms.ads.internal.client.N n) {
        com.google.android.gms.ads.c cVarA = com.google.android.gms.ads.c.a(zzfpVar.b);
        if (cVarA == null) {
            return null;
        }
        int iOrdinal = cVarA.ordinal();
        VersionInfoParcel versionInfoParcel = this.b;
        Context context = this.a;
        if (iOrdinal == 1) {
            int i = versionInfoParcel.c;
            InterfaceC2825xa interfaceC2825xa = this.e;
            C2713ur c2713urB = b();
            return new C2670tr(this.d, context, i, interfaceC2825xa, zzfpVar, n, this.c, c2713urB, this.f, 1);
        }
        if (iOrdinal == 2) {
            int i2 = versionInfoParcel.c;
            InterfaceC2825xa interfaceC2825xa2 = this.e;
            C2713ur c2713urB2 = b();
            return new C2670tr(this.d, context, i2, interfaceC2825xa2, zzfpVar, n, this.c, c2713urB2, this.f, 2);
        }
        if (iOrdinal != 5) {
            return null;
        }
        int i3 = versionInfoParcel.c;
        InterfaceC2825xa interfaceC2825xa3 = this.e;
        C2713ur c2713urB3 = b();
        return new C2670tr(this.d, context, i3, interfaceC2825xa3, zzfpVar, n, this.c, c2713urB3, this.f, 0);
    }
}
