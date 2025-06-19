package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class O1 extends AbstractC3787c1 {
    private static final O1 zzb;
    private int zzd;
    private int zze;
    private int zzg;
    private String zzf = "";
    private String zzh = "";

    static {
        O1 o1 = new O1();
        zzb = o1;
        AbstractC3787c1.k(O1.class, o1);
    }

    public static /* synthetic */ void n(O1 o1, String str) {
        o1.zzd |= 8;
        o1.zzh = str;
    }

    public static /* synthetic */ void o(O1 o1, String str) {
        str.getClass();
        o1.zzd |= 2;
        o1.zzf = str;
    }

    public static /* synthetic */ void p(O1 o1, int i) {
        o1.zzd |= 1;
        o1.zze = i;
    }

    public static /* synthetic */ void q(O1 o1, int i) {
        o1.zzg = i - 1;
        o1.zzd |= 4;
    }

    public static N1 r() {
        return (N1) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0004\u0000\u0001\u0001\u0005\u0004\u0000\u0000\u0000\u0001င\u0000\u0002ဈ\u0001\u0004᠌\u0002\u0005ဈ\u0003", new Object[]{"zzd", "zze", "zzf", "zzg", O0.d, "zzh"});
        }
        if (i2 == 3) {
            return new O1();
        }
        if (i2 == 4) {
            return new N1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
