package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class Y1 extends AbstractC3787c1 {
    private static final Y1 zzb;
    private int zzd;
    private int zze;

    static {
        Y1 y1 = new Y1();
        zzb = y1;
        AbstractC3787c1.k(Y1.class, y1);
    }

    public static /* synthetic */ void n(Y1 y1, int i) {
        y1.zze = i - 1;
        y1.zzd |= 1;
    }

    public static W1 o() {
        return (W1) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001᠌\u0000", new Object[]{"zzd", "zze", O0.g});
        }
        if (i2 == 3) {
            return new Y1();
        }
        if (i2 == 4) {
            return new W1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
