package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class L0 extends W1 {
    private static final L0 zzb;
    private int zzd;
    private long zzh;
    private long zzl;
    private String zze = "";
    private String zzf = "";
    private String zzg = "";
    private String zzi = "";
    private String zzj = "";
    private String zzk = "";

    static {
        L0 l0 = new L0();
        zzb = l0;
        W1.j(L0.class, l0);
    }

    public static /* synthetic */ void F(L0 l0) {
        l0.zzd &= -5;
        l0.zzg = zzb.zzg;
    }

    public static /* synthetic */ void G(L0 l0) {
        l0.zzd &= -3;
        l0.zzf = zzb.zzf;
    }

    public static /* synthetic */ void H(L0 l0) {
        l0.zzd &= -2;
        l0.zze = zzb.zze;
    }

    public static /* synthetic */ void I(L0 l0) {
        l0.zzd &= -65;
        l0.zzk = zzb.zzk;
    }

    public static /* synthetic */ void J(L0 l0) {
        l0.zzd &= -33;
        l0.zzj = zzb.zzj;
    }

    public static /* synthetic */ void K(L0 l0) {
        l0.zzd &= -17;
        l0.zzi = zzb.zzi;
    }

    public static /* synthetic */ void L(L0 l0, String str) {
        l0.zzd |= 4;
        l0.zzg = str;
    }

    public static /* synthetic */ void M(L0 l0, String str) {
        l0.zzd |= 2;
        l0.zzf = str;
    }

    public static /* synthetic */ void N(L0 l0, String str) {
        l0.zzd |= 1;
        l0.zze = str;
    }

    public static /* synthetic */ void O(L0 l0, long j) {
        l0.zzd |= 8;
        l0.zzh = j;
    }

    public static /* synthetic */ void P(L0 l0, long j) {
        l0.zzd |= 128;
        l0.zzl = j;
    }

    public static /* synthetic */ void Q(L0 l0, String str) {
        l0.zzd |= 64;
        l0.zzk = str;
    }

    public static /* synthetic */ void R(L0 l0, String str) {
        l0.zzd |= 32;
        l0.zzj = str;
    }

    public static /* synthetic */ void S(L0 l0, String str) {
        l0.zzd |= 16;
        l0.zzi = str;
    }

    public static K0 x() {
        return (K0) zzb.e();
    }

    public static L0 y() {
        return zzb;
    }

    public final String A() {
        return this.zzf;
    }

    public final String B() {
        return this.zze;
    }

    public final String C() {
        return this.zzk;
    }

    public final String D() {
        return this.zzj;
    }

    public final String E() {
        return this.zzi;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\b\u0000\u0001\u0001\b\b\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဈ\u0002\u0004ဂ\u0003\u0005ဈ\u0004\u0006ဈ\u0005\u0007ဈ\u0006\bဂ\u0007", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk", "zzl"});
        }
        if (i2 == 3) {
            return new L0();
        }
        if (i2 == 4) {
            return new K0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final boolean n() {
        return (this.zzd & 4) != 0;
    }

    public final boolean o() {
        return (this.zzd & 2) != 0;
    }

    public final boolean p() {
        return (this.zzd & 1) != 0;
    }

    public final boolean q() {
        return (this.zzd & 8) != 0;
    }

    public final boolean r() {
        return (this.zzd & 128) != 0;
    }

    public final boolean s() {
        return (this.zzd & 64) != 0;
    }

    public final boolean t() {
        return (this.zzd & 32) != 0;
    }

    public final boolean u() {
        return (this.zzd & 16) != 0;
    }

    public final long v() {
        return this.zzh;
    }

    public final long w() {
        return this.zzl;
    }

    public final String z() {
        return this.zzg;
    }
}
