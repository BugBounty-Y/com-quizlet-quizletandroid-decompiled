package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class g2 extends AbstractC3787c1 {
    private static final g2 zzb;
    private int zzd;
    private int zze;

    static {
        g2 g2Var = new g2();
        zzb = g2Var;
        AbstractC3787c1.k(g2.class, g2Var);
    }

    public static g2 n() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001᠌\u0000", new Object[]{"zzd", "zze", O0.i});
        }
        if (i2 == 3) {
            return new g2();
        }
        if (i2 == 4) {
            return new P1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
