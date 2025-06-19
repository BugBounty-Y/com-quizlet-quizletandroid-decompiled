package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.concurrent.ScheduledExecutorService;

/* loaded from: classes2.dex */
public final class Lq {
    public static final Tv d = Tv.b;
    public final C2227jd a;
    public final ScheduledExecutorService b;
    public final Kq c;

    public Lq(C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, Kq kq) {
        this.a = c2227jd;
        this.b = scheduledExecutorService;
        this.c = kq;
    }

    public final C2084g6 a(com.google.common.util.concurrent.e eVar, Object obj) {
        return new C2084g6(this, obj, null, eVar, Collections.singletonList(eVar), eVar);
    }
}
