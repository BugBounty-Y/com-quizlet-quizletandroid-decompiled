package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class U1 extends AbstractC3787c1 {
    private static final U1 zzb;
    private int zzd;
    private String zze = "";
    private String zzf = "";
    private int zzg;
    private long zzh;

    static {
        U1 u1 = new U1();
        zzb = u1;
        AbstractC3787c1.k(U1.class, u1);
    }

    public static /* synthetic */ void n(U1 u1, int i) {
        u1.zzd |= 4;
        u1.zzg = i;
    }

    public static /* synthetic */ void o(U1 u1, long j) {
        u1.zzd |= 8;
        u1.zzh = j;
    }

    public static /* synthetic */ void p(U1 u1, String str) {
        str.getClass();
        u1.zzd |= 2;
        u1.zzf = str;
    }

    public static /* synthetic */ void q(U1 u1, String str) {
        str.getClass();
        u1.zzd |= 1;
        u1.zze = str;
    }

    public static T1 r() {
        return (T1) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003င\u0002\u0004ဂ\u0003", new Object[]{"zzd", "zze", "zzf", "zzg", "zzh"});
        }
        if (i2 == 3) {
            return new U1();
        }
        if (i2 == 4) {
            return new T1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
