package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.cp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1935cp implements Vo {
    public final com.google.android.gms.ads.internal.util.C a;
    public final Context b;
    public final C2227jd c;
    public final ScheduledExecutorService d;
    public final Ts e;
    public final C2023eq f;
    public final VersionInfoParcel g;

    public C1935cp(com.google.android.gms.ads.internal.util.C c, Context context, C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, Ts ts, C2023eq c2023eq, VersionInfoParcel versionInfoParcel) {
        this.a = c;
        this.b = context;
        this.c = c2227jd;
        this.d = scheduledExecutorService;
        this.e = ts;
        this.f = c2023eq;
        this.g = versionInfoParcel;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        return 56;
    }

    /* JADX WARN: Code restructure failed: missing block: B:39:0x00c0, code lost:
    
        if (java.util.Arrays.asList(r0.split(",")).contains(r9.b.getPackageName()) == false) goto L48;
     */
    @Override // com.google.android.gms.internal.ads.Vo
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.common.util.concurrent.e zzb() {
        /*
            Method dump skipped, instructions count: 301
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1935cp.zzb():com.google.common.util.concurrent.e");
    }
}
