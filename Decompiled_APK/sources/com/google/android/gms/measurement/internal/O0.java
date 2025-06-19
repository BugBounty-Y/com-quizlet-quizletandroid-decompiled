package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import android.os.SystemClock;
import com.google.android.gms.internal.measurement.zzdj;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class O0 extends AbstractC3888q {
    public volatile L0 d;
    public volatile L0 e;
    public L0 f;
    public final ConcurrentHashMap g;
    public zzdj h;
    public volatile boolean i;
    public volatile L0 j;
    public L0 k;
    public boolean l;
    public final Object m;

    public O0(Y y) {
        super(y);
        this.m = new Object();
        this.g = new ConcurrentHashMap();
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return false;
    }

    public final void V(String str, L0 l0, boolean z) {
        L0 l02;
        L0 l03 = this.d == null ? this.e : this.d;
        if (l0.b == null) {
            l02 = new L0(l0.a, str != null ? Z(str) : null, l0.c, l0.e, l0.f);
        } else {
            l02 = l0;
        }
        this.e = this.d;
        this.d = l02;
        Y y = (Y) this.b;
        y.n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        X x = y.j;
        Y.k(x);
        x.c0(new M0(this, l02, l03, jElapsedRealtime, z));
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x002d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void W(com.google.android.gms.measurement.internal.L0 r18, com.google.android.gms.measurement.internal.L0 r19, long r20, boolean r22, android.os.Bundle r23) {
        /*
            Method dump skipped, instructions count: 221
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.O0.W(com.google.android.gms.measurement.internal.L0, com.google.android.gms.measurement.internal.L0, long, boolean, android.os.Bundle):void");
    }

    public final void X(L0 l0, boolean z, long j) {
        Y y = (Y) this.b;
        C3884o c3884o = y.q;
        Y.g(c3884o);
        y.n.getClass();
        c3884o.V(SystemClock.elapsedRealtime());
        boolean z2 = l0 != null && l0.d;
        g1 g1Var = y.k;
        Y.j(g1Var);
        if (!g1Var.g.k(j, z2, z) || l0 == null) {
            return;
        }
        l0.d = false;
    }

    public final L0 Y(boolean z) {
        Q();
        S();
        if (!z) {
            return this.f;
        }
        L0 l0 = this.f;
        return l0 != null ? l0 : this.k;
    }

    public final String Z(String str) {
        if (str == null) {
            return "Activity";
        }
        String[] strArrSplit = str.split("\\.");
        int length = strArrSplit.length;
        String str2 = length > 0 ? strArrSplit[length - 1] : "";
        int length2 = str2.length();
        Y y = (Y) this.b;
        y.g.getClass();
        if (length2 <= 500) {
            return str2;
        }
        y.g.getClass();
        return str2.substring(0, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
    }

    public final void a0(zzdj zzdjVar, Bundle bundle) {
        Bundle bundle2;
        if (!((Y) this.b).g.g0() || bundle == null || (bundle2 = bundle.getBundle("com.google.app_measurement.screen_service")) == null) {
            return;
        }
        this.g.put(Integer.valueOf(zzdjVar.a), new L0(bundle2.getLong("id"), bundle2.getString("name"), bundle2.getString("referrer_name")));
    }

    public final L0 b0(zzdj zzdjVar) {
        com.google.android.gms.common.internal.u.h(zzdjVar);
        Integer numValueOf = Integer.valueOf(zzdjVar.a);
        ConcurrentHashMap concurrentHashMap = this.g;
        L0 l0 = (L0) concurrentHashMap.get(numValueOf);
        if (l0 == null) {
            String strZ = Z(zzdjVar.b);
            x1 x1Var = ((Y) this.b).l;
            Y.h(x1Var);
            L0 l02 = new L0(x1Var.b1(), null, strZ);
            concurrentHashMap.put(numValueOf, l02);
            l0 = l02;
        }
        return this.j != null ? this.j : l0;
    }
}
