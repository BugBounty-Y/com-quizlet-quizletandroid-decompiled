package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class D1 extends F1 {
    @Override // com.google.android.gms.internal.play_billing.F1
    public final double a(long j, Object obj) {
        return Double.longBitsToDouble(this.a.getLong(obj, j));
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final float b(long j, Object obj) {
        return Float.intBitsToFloat(this.a.getInt(obj, j));
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final void c(Object obj, long j, boolean z) {
        if (G1.g) {
            G1.b(obj, j, z ? (byte) 1 : (byte) 0);
        } else {
            G1.c(obj, j, z ? (byte) 1 : (byte) 0);
        }
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final void d(Object obj, long j, byte b) {
        if (G1.g) {
            G1.b(obj, j, b);
        } else {
            G1.c(obj, j, b);
        }
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final void e(Object obj, long j, double d) {
        this.a.putLong(obj, j, Double.doubleToLongBits(d));
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final void f(Object obj, long j, float f) {
        this.a.putInt(obj, j, Float.floatToIntBits(f));
    }

    @Override // com.google.android.gms.internal.play_billing.F1
    public final boolean g(long j, Object obj) {
        return G1.g ? G1.l(j, obj) : G1.m(j, obj);
    }
}
