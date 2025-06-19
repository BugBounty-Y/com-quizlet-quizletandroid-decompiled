package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class N0 extends AbstractC3787c1 {
    private static final N0 zzb;
    private int zzd;
    private String zze = "";

    static {
        N0 n0 = new N0();
        zzb = n0;
        AbstractC3787c1.k(N0.class, n0);
    }

    public static M0 n() {
        return (M0) zzb.f();
    }

    public static /* synthetic */ void o(N0 n0, String str) {
        n0.zzd |= 1;
        n0.zze = str;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001ဈ\u0000", new Object[]{"zzd", "zze"});
        }
        if (i2 == 3) {
            return new N0();
        }
        if (i2 == 4) {
            return new M0(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
