package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class i2 extends AbstractC3787c1 {
    private static final i2 zzb;
    private int zzd;
    private int zze;
    private boolean zzf;

    static {
        i2 i2Var = new i2();
        zzb = i2Var;
        AbstractC3787c1.k(i2.class, i2Var);
    }

    public static /* synthetic */ void n(i2 i2Var) {
        i2Var.zzd |= 2;
        i2Var.zzf = true;
    }

    public static h2 o() {
        return (h2) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001င\u0000\u0002ဇ\u0001", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new i2();
        }
        if (i2 == 4) {
            return new h2(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
