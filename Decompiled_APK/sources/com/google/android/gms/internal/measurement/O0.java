package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class O0 extends W1 {
    private static final O0 zzb;
    private int zzd;
    private boolean zze;
    private boolean zzf;
    private boolean zzg;
    private boolean zzh;
    private boolean zzi;
    private boolean zzj;
    private boolean zzk;

    static {
        O0 o0 = new O0();
        zzb = o0;
        W1.j(O0.class, o0);
    }

    public static N0 n() {
        return (N0) zzb.e();
    }

    public static O0 o() {
        return zzb;
    }

    public static /* synthetic */ void p(O0 o0, boolean z) {
        o0.zzd |= 32;
        o0.zzj = z;
    }

    public static /* synthetic */ void q(O0 o0, boolean z) {
        o0.zzd |= 16;
        o0.zzi = z;
    }

    public static /* synthetic */ void r(O0 o0, boolean z) {
        o0.zzd |= 1;
        o0.zze = z;
    }

    public static /* synthetic */ void s(O0 o0, boolean z) {
        o0.zzd |= 64;
        o0.zzk = z;
    }

    public static /* synthetic */ void t(O0 o0, boolean z) {
        o0.zzd |= 2;
        o0.zzf = z;
    }

    public static /* synthetic */ void u(O0 o0, boolean z) {
        o0.zzd |= 4;
        o0.zzg = z;
    }

    public static /* synthetic */ void v(O0 o0, boolean z) {
        o0.zzd |= 8;
        o0.zzh = z;
    }

    public final boolean A() {
        return this.zzf;
    }

    public final boolean B() {
        return this.zzg;
    }

    public final boolean C() {
        return this.zzh;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0007\u0000\u0001\u0001\u0007\u0007\u0000\u0000\u0000\u0001ဇ\u0000\u0002ဇ\u0001\u0003ဇ\u0002\u0004ဇ\u0003\u0005ဇ\u0004\u0006ဇ\u0005\u0007ဇ\u0006", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk"});
        }
        if (i2 == 3) {
            return new O0();
        }
        if (i2 == 4) {
            return new N0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final boolean w() {
        return this.zzj;
    }

    public final boolean x() {
        return this.zzi;
    }

    public final boolean y() {
        return this.zze;
    }

    public final boolean z() {
        return this.zzk;
    }
}
