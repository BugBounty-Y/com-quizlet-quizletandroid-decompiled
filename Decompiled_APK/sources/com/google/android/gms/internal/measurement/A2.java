package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class A2 extends B2 {
    @Override // com.google.android.gms.internal.measurement.B2
    public final double a(long j, Object obj) {
        return Double.longBitsToDouble(this.a.getLong(obj, j));
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final float b(long j, Object obj) {
        return Float.intBitsToFloat(this.a.getInt(obj, j));
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final void c(Object obj, long j, boolean z) {
        if (C2.g) {
            C2.b(obj, j, z ? (byte) 1 : (byte) 0);
        } else {
            C2.c(obj, j, z ? (byte) 1 : (byte) 0);
        }
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final void d(Object obj, long j, byte b) {
        if (C2.g) {
            C2.b(obj, j, b);
        } else {
            C2.c(obj, j, b);
        }
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final void e(Object obj, long j, double d) {
        this.a.putLong(obj, j, Double.doubleToLongBits(d));
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final void f(Object obj, long j, float f) {
        this.a.putInt(obj, j, Float.floatToIntBits(f));
    }

    @Override // com.google.android.gms.internal.measurement.B2
    public final boolean g(long j, Object obj) {
        return C2.g ? C2.l(j, obj) : C2.m(j, obj);
    }
}
