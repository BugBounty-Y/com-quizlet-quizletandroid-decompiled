package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class S1 extends AbstractC3787c1 {
    private static final S1 zzb;
    private int zzd;
    private int zzf;
    private O1 zzi;
    private boolean zzj;
    private boolean zzk;
    private String zze = "";
    private InterfaceC3796f1 zzg = C3790d1.e;
    private InterfaceC3799g1 zzh = C3846w1.e;

    static {
        S1 s1 = new S1();
        zzb = s1;
        AbstractC3787c1.k(S1.class, s1);
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0007\u0000\u0001\u0001\u0007\u0007\u0000\u0002\u0000\u0001ဈ\u0000\u0002᠌\u0001\u0003ࠬ\u0004\u001b\u0005ဉ\u0002\u0006ဇ\u0003\u0007ဇ\u0004", new Object[]{"zzd", "zze", "zzf", O0.f, "zzg", O0.e, "zzh", d2.class, "zzi", "zzj", "zzk"});
        }
        if (i2 == 3) {
            return new S1();
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
