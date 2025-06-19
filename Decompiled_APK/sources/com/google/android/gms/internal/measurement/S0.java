package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class S0 extends W1 {
    private static final S0 zzb;
    private int zzd;
    private int zze;
    private long zzf;

    static {
        S0 s0 = new S0();
        zzb = s0;
        W1.j(S0.class, s0);
    }

    public static R0 p() {
        return (R0) zzb.e();
    }

    public static /* synthetic */ void q(S0 s0, long j) {
        s0.zzd |= 2;
        s0.zzf = j;
    }

    public static /* synthetic */ void r(S0 s0, int i) {
        s0.zzd |= 1;
        s0.zze = i;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001င\u0000\u0002ဂ\u0001", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new S0();
        }
        if (i2 == 4) {
            return new R0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zze;
    }

    public final long o() {
        return this.zzf;
    }

    public final boolean s() {
        return (this.zzd & 2) != 0;
    }

    public final boolean t() {
        return (this.zzd & 1) != 0;
    }
}
