package com.google.android.gms.measurement.internal;

/* loaded from: classes2.dex */
public final class q1 {
    public final r1 a;
    public int b = 1;
    public long c = a();

    public q1(r1 r1Var) {
        this.a = r1Var;
    }

    public final long a() {
        r1 r1Var = this.a;
        com.google.android.gms.common.internal.u.h(r1Var);
        long jLongValue = ((Long) AbstractC3893t.v.a(null)).longValue();
        long jLongValue2 = ((Long) AbstractC3893t.w.a(null)).longValue();
        for (int i = 1; i < this.b; i++) {
            jLongValue += jLongValue;
            if (jLongValue >= jLongValue2) {
                break;
            }
        }
        ((com.google.android.gms.common.util.b) r1Var.f()).getClass();
        return Math.min(jLongValue, jLongValue2) + System.currentTimeMillis();
    }
}
