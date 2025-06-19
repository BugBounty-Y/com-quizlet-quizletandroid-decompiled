package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class Q0 extends W1 {
    private static final Q0 zzb;
    private int zzd;
    private int zze;
    private C2989f1 zzf;
    private C2989f1 zzg;
    private boolean zzh;

    static {
        Q0 q0 = new Q0();
        zzb = q0;
        W1.j(Q0.class, q0);
    }

    public static P0 o() {
        return (P0) zzb.e();
    }

    public static /* synthetic */ void r(Q0 q0, int i) {
        q0.zzd |= 1;
        q0.zze = i;
    }

    public static /* synthetic */ void s(Q0 q0, C2989f1 c2989f1) {
        q0.zzf = c2989f1;
        q0.zzd |= 2;
    }

    public static /* synthetic */ void t(Q0 q0, boolean z) {
        q0.zzd |= 8;
        q0.zzh = z;
    }

    public static /* synthetic */ void u(Q0 q0, C2989f1 c2989f1) {
        q0.zzg = c2989f1;
        q0.zzd |= 4;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001င\u0000\u0002ဉ\u0001\u0003ဉ\u0002\u0004ဇ\u0003", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh"});
        }
        if (i2 == 3) {
            return new Q0();
        }
        if (i2 == 4) {
            return new P0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zze;
    }

    public final C2989f1 p() {
        C2989f1 c2989f1 = this.zzf;
        return c2989f1 == null ? C2989f1.s() : c2989f1;
    }

    public final C2989f1 q() {
        C2989f1 c2989f1 = this.zzg;
        return c2989f1 == null ? C2989f1.s() : c2989f1;
    }

    public final boolean v() {
        return this.zzh;
    }

    public final boolean w() {
        return (this.zzd & 1) != 0;
    }

    public final boolean x() {
        return (this.zzd & 8) != 0;
    }

    public final boolean y() {
        return (this.zzd & 4) != 0;
    }
}
