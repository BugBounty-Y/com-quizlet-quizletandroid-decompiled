package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class V1 extends AbstractC3787c1 {
    private static final V1 zzb;
    private int zzd;
    private boolean zze;
    private boolean zzf;

    static {
        V1 v1 = new V1();
        zzb = v1;
        AbstractC3787c1.k(V1.class, v1);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဇ\u0000\u0002ဇ\u0001", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new V1();
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
