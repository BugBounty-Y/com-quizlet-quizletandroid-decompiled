package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class c2 extends AbstractC3787c1 {
    private static final c2 zzb;
    private int zzd;
    private int zze = 0;
    private Object zzf;
    private U1 zzg;
    private V1 zzh;

    static {
        c2 c2Var = new c2();
        zzb = c2Var;
        AbstractC3787c1.k(c2.class, c2Var);
    }

    public static /* synthetic */ void n(c2 c2Var, K1 k1) {
        c2Var.zzf = k1;
        c2Var.zze = 2;
    }

    public static /* synthetic */ void o(c2 c2Var, M1 m1) {
        c2Var.zzf = m1;
        c2Var.zze = 3;
    }

    public static /* synthetic */ void p(c2 c2Var, Q1 q1) {
        q1.getClass();
        c2Var.zzf = q1;
        c2Var.zze = 7;
    }

    public static /* synthetic */ void q(c2 c2Var, U1 u1) {
        u1.getClass();
        c2Var.zzg = u1;
        c2Var.zzd |= 1;
    }

    public static /* synthetic */ void r(c2 c2Var, f2 f2Var) {
        c2Var.zzf = f2Var;
        c2Var.zze = 8;
    }

    public static /* synthetic */ void s(c2 c2Var, g2 g2Var) {
        c2Var.zzf = g2Var;
        c2Var.zze = 4;
    }

    public static b2 t() {
        return (b2) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\b\u0001\u0001\u0001\b\b\u0000\u0000\u0000\u0001ဉ\u0000\u0002<\u0000\u0003<\u0000\u0004<\u0000\u0005<\u0000\u0006ဉ\u0001\u0007<\u0000\b<\u0000", new Object[]{"zzf", "zze", "zzd", "zzg", K1.class, M1.class, g2.class, S1.class, "zzh", Q1.class, f2.class});
        }
        if (i2 == 3) {
            return new c2();
        }
        if (i2 == 4) {
            return new b2(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
