package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.l1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3019l1 extends W1 {
    private static final C3019l1 zzb;
    private int zzd;
    private long zze;
    private String zzf = "";
    private String zzg = "";
    private long zzh;
    private float zzi;
    private double zzj;

    static {
        C3019l1 c3019l1 = new C3019l1();
        zzb = c3019l1;
        W1.j(C3019l1.class, c3019l1);
    }

    public static /* synthetic */ void A(C3019l1 c3019l1, long j) {
        c3019l1.zzd |= 1;
        c3019l1.zze = j;
    }

    public static /* synthetic */ void B(C3019l1 c3019l1, String str) {
        str.getClass();
        c3019l1.zzd |= 4;
        c3019l1.zzg = str;
    }

    public static C3014k1 r() {
        return (C3014k1) zzb.e();
    }

    public static /* synthetic */ void u(C3019l1 c3019l1) {
        c3019l1.zzd &= -33;
        c3019l1.zzj = 0.0d;
    }

    public static /* synthetic */ void v(C3019l1 c3019l1) {
        c3019l1.zzd &= -9;
        c3019l1.zzh = 0L;
    }

    public static /* synthetic */ void w(C3019l1 c3019l1) {
        c3019l1.zzd &= -5;
        c3019l1.zzg = zzb.zzg;
    }

    public static /* synthetic */ void x(C3019l1 c3019l1, double d) {
        c3019l1.zzd |= 32;
        c3019l1.zzj = d;
    }

    public static /* synthetic */ void y(C3019l1 c3019l1, long j) {
        c3019l1.zzd |= 8;
        c3019l1.zzh = j;
    }

    public static /* synthetic */ void z(C3019l1 c3019l1, String str) {
        str.getClass();
        c3019l1.zzd |= 2;
        c3019l1.zzf = str;
    }

    public final boolean C() {
        return (this.zzd & 32) != 0;
    }

    public final boolean D() {
        return (this.zzd & 16) != 0;
    }

    public final boolean E() {
        return (this.zzd & 8) != 0;
    }

    public final boolean F() {
        return (this.zzd & 1) != 0;
    }

    public final boolean G() {
        return (this.zzd & 4) != 0;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0000\u0000\u0001ဂ\u0000\u0002ဈ\u0001\u0003ဈ\u0002\u0004ဂ\u0003\u0005ခ\u0004\u0006က\u0005", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj"});
        }
        if (i2 == 3) {
            return new C3019l1();
        }
        if (i2 == 4) {
            return new C3014k1(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final double n() {
        return this.zzj;
    }

    public final float o() {
        return this.zzi;
    }

    public final long p() {
        return this.zzh;
    }

    public final long q() {
        return this.zze;
    }

    public final String s() {
        return this.zzf;
    }

    public final String t() {
        return this.zzg;
    }
}
