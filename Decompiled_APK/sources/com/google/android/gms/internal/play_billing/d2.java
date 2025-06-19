package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class d2 extends AbstractC3787c1 {
    private static final d2 zzb;
    private int zzd;
    private int zzf;
    private InterfaceC3799g1 zze = C3846w1.e;
    private String zzg = "";

    static {
        d2 d2Var = new d2();
        zzb = d2Var;
        AbstractC3787c1.k(d2.class, d2Var);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0001\u0000\u0001\u001a\u0002င\u0000\u0003ဈ\u0001", new Object[]{"zzd", "zze", "zzf", "zzg"});
        }
        if (i2 == 3) {
            return new d2();
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
