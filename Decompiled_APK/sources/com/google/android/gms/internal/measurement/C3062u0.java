package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.u0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3062u0 extends W1 {
    private static final C3062u0 zzb;
    private int zzd;
    private int zze;
    private String zzf = "";
    private C3038p0 zzg;
    private boolean zzh;
    private boolean zzi;
    private boolean zzj;

    static {
        C3062u0 c3062u0 = new C3062u0();
        zzb = c3062u0;
        W1.j(C3062u0.class, c3062u0);
    }

    public static C3057t0 p() {
        return (C3057t0) zzb.e();
    }

    public static /* synthetic */ void r(C3062u0 c3062u0, String str) {
        c3062u0.zzd |= 2;
        c3062u0.zzf = str;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0000\u0000\u0001င\u0000\u0002ဈ\u0001\u0003ဉ\u0002\u0004ဇ\u0003\u0005ဇ\u0004\u0006ဇ\u0005", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj"});
        }
        if (i2 == 3) {
            return new C3062u0();
        }
        if (i2 == 4) {
            return new C3057t0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zze;
    }

    public final C3038p0 o() {
        C3038p0 c3038p0 = this.zzg;
        return c3038p0 == null ? C3038p0.n() : c3038p0;
    }

    public final String q() {
        return this.zzf;
    }

    public final boolean s() {
        return this.zzh;
    }

    public final boolean t() {
        return this.zzi;
    }

    public final boolean u() {
        return this.zzj;
    }

    public final boolean v() {
        return (this.zzd & 1) != 0;
    }

    public final boolean w() {
        return (this.zzd & 32) != 0;
    }
}
