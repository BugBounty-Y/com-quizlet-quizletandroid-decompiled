package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.m5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2342m5 extends AbstractCallableC2599s5 {
    public final HashMap h;
    public final View i;
    public final Context j;

    public C2342m5(Z4 z4, C1864b4 c1864b4, int i, HashMap map, View view, Context context) {
        super(z4, "q8irn8XqClynUBOsRuq73Jawzwc3gJeVDnk3iDYtMcevrbEAuNWFzcNhN+feXrfp", "dam+Wb9GR7yMSr36KIsK6PGM3yrtzGfNR9lAtk4lliE=", c1864b4, i, 85);
        this.h = map;
        this.i = view;
        this.j = context;
    }

    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    public final void a() {
        HashMap map = this.h;
        long jLongValue = map.containsKey(1) ? ((Long) map.get(1)).longValue() : Long.MIN_VALUE;
        HashMap map2 = this.h;
        long[] jArr = {jLongValue, map2.containsKey(2) ? ((Long) map2.get(2)).longValue() : Long.MIN_VALUE};
        Context context = this.j;
        if (context == null) {
            context = this.a.a;
        }
        long[] jArr2 = (long[]) this.e.invoke(null, jArr, context, this.i);
        long j = jArr2[0];
        HashMap map3 = this.h;
        map3.put(1, Long.valueOf(jArr2[1]));
        long j2 = jArr2[2];
        map3.put(2, Long.valueOf(jArr2[3]));
        C1864b4 c1864b4 = this.d;
        synchronized (c1864b4) {
            c1864b4.e();
            C2384n4.w((C2384n4) c1864b4.b, j);
            c1864b4.e();
            C2384n4.G0((C2384n4) c1864b4.b, j2);
        }
    }
}
