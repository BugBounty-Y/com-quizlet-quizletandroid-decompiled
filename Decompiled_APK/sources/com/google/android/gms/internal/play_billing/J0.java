package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class J0 extends AbstractC3787c1 {
    private static final J0 zzb;
    private int zzd;
    private N0 zze;
    private N0 zzf;
    private int zzg;

    static {
        J0 j0 = new J0();
        zzb = j0;
        AbstractC3787c1.k(J0.class, j0);
    }

    public static I0 n() {
        return (I0) zzb.f();
    }

    public static /* synthetic */ void o(J0 j0, N0 n0) {
        j0.zze = n0;
        j0.zzd |= 1;
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဉ\u0000\u0002ဉ\u0001\u0003᠌\u0002", new Object[]{"zzd", "zze", "zzf", "zzg", O0.b});
        }
        if (i2 == 3) {
            return new J0();
        }
        if (i2 == 4) {
            return new I0(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
