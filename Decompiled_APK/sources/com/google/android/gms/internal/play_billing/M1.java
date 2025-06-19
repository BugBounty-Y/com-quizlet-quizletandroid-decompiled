package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class M1 extends AbstractC3787c1 {
    private static final M1 zzb;
    private int zzd;
    private int zze = 0;
    private Object zzf;
    private int zzg;

    static {
        M1 m1 = new M1();
        zzb = m1;
        AbstractC3787c1.k(M1.class, m1);
    }

    public static /* synthetic */ void n(M1 m1, Y1 y1) {
        m1.zzf = y1;
        m1.zze = 2;
    }

    public static /* synthetic */ void o(M1 m1, i2 i2Var) {
        m1.zzf = i2Var;
        m1.zze = 3;
    }

    public static /* synthetic */ void p(M1 m1, int i) {
        m1.zzg = i - 1;
        m1.zzd |= 1;
    }

    public static L1 q() {
        return (L1) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0004\u0001\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001᠌\u0000\u0002<\u0000\u0003<\u0000\u0004<\u0000", new Object[]{"zzf", "zze", "zzd", "zzg", O0.c, Y1.class, i2.class, a2.class});
        }
        if (i2 == 3) {
            return new M1();
        }
        if (i2 == 4) {
            return new L1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
