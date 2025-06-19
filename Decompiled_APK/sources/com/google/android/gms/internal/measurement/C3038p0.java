package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.p0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3038p0 extends W1 {
    private static final C3038p0 zzb;
    private int zzd;
    private C3067v0 zze;
    private C3052s0 zzf;
    private boolean zzg;
    private String zzh = "";

    static {
        C3038p0 c3038p0 = new C3038p0();
        zzb = c3038p0;
        W1.j(C3038p0.class, c3038p0);
    }

    public static C3038p0 n() {
        return zzb;
    }

    public static /* synthetic */ void r(C3038p0 c3038p0, String str) {
        c3038p0.zzd |= 8;
        c3038p0.zzh = str;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ဉ\u0000\u0002ဉ\u0001\u0003ဇ\u0002\u0004ဈ\u0003", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh"});
        }
        if (i2 == 3) {
            return new C3038p0();
        }
        if (i2 == 4) {
            return new C3033o0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final C3052s0 o() {
        C3052s0 c3052s0 = this.zzf;
        return c3052s0 == null ? C3052s0.n() : c3052s0;
    }

    public final C3067v0 p() {
        C3067v0 c3067v0 = this.zze;
        return c3067v0 == null ? C3067v0.o() : c3067v0;
    }

    public final String q() {
        return this.zzh;
    }

    public final boolean s() {
        return this.zzg;
    }

    public final boolean t() {
        return (this.zzd & 4) != 0;
    }

    public final boolean u() {
        return (this.zzd & 2) != 0;
    }

    public final boolean v() {
        return (this.zzd & 8) != 0;
    }

    public final boolean w() {
        return (this.zzd & 1) != 0;
    }
}
