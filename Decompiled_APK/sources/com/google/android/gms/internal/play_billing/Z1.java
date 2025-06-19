package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class Z1 extends AbstractC3787c1 {
    private static final Z1 zzb;
    private int zzd;
    private int zze;
    private String zzf = "";

    static {
        Z1 z1 = new Z1();
        zzb = z1;
        AbstractC3787c1.k(Z1.class, z1);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001᠌\u0000\u0002ဈ\u0001", new Object[]{"zzd", "zze", O0.h, "zzf"});
        }
        if (i2 == 3) {
            return new Z1();
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
