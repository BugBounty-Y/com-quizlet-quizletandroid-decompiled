package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class Q1 extends AbstractC3787c1 {
    private static final Q1 zzb;

    static {
        Q1 q1 = new Q1();
        zzb = q1;
        AbstractC3787c1.k(Q1.class, q1);
    }

    public static Q1 n() {
        return zzb;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0000", null);
        }
        if (i2 == 3) {
            return new Q1();
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
