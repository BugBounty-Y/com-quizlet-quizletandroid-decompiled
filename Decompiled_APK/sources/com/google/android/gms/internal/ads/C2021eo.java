package com.google.android.gms.internal.ads;

import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.eo, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2021eo implements Vo {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;

    public C2021eo(C2010ed c2010ed, ScheduledExecutorService scheduledExecutorService, C2227jd c2227jd) {
        this.a = 4;
        this.b = c2010ed;
        this.d = scheduledExecutorService;
        this.c = c2227jd;
    }

    @Override // com.google.android.gms.internal.ads.Vo
    public final int zza() {
        switch (this.a) {
            case 0:
                return 6;
            case 1:
                return 9;
            case 2:
                return 29;
            case 3:
                return 34;
            default:
                return 43;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x0106  */
    @Override // com.google.android.gms.internal.ads.Vo
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.common.util.concurrent.e zzb() throws android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 380
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2021eo.zzb():com.google.common.util.concurrent.e");
    }

    public /* synthetic */ C2021eo(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }
}
