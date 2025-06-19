package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class a2 extends AbstractC3787c1 {
    private static final a2 zzb;
    private InterfaceC3799g1 zzd = C3846w1.e;

    static {
        a2 a2Var = new a2();
        zzb = a2Var;
        AbstractC3787c1.k(a2.class, a2Var);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001b", new Object[]{"zzd", Z1.class});
        }
        if (i2 == 3) {
            return new a2();
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
