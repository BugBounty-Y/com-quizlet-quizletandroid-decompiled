package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class f2 extends AbstractC3787c1 {
    private static final f2 zzb;
    private int zzd;
    private O1 zze;

    static {
        f2 f2Var = new f2();
        zzb = f2Var;
        AbstractC3787c1.k(f2.class, f2Var);
    }

    public static /* synthetic */ void n(f2 f2Var, O1 o1) {
        f2Var.zze = o1;
        f2Var.zzd |= 1;
    }

    public static e2 o() {
        return (e2) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0001\u0000\u0001\u0001\u0001\u0001\u0000\u0000\u0000\u0001ဉ\u0000", new Object[]{"zzd", "zze"});
        }
        if (i2 == 3) {
            return new f2();
        }
        if (i2 == 4) {
            return new e2(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
