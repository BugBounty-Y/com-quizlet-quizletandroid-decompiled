package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class A0 extends W1 {
    private static final A0 zzb;
    private int zzd;
    private String zze = "";
    private InterfaceC2975c2 zzf = C3059t2.e;
    private boolean zzg;

    static {
        A0 a0 = new A0();
        zzb = a0;
        W1.j(A0.class, a0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0001\u0000\u0001ဈ\u0000\u0002\u001b\u0003ဇ\u0001", new Object[]{"zzd", "zze", "zzf", H0.class, "zzg"});
        }
        if (i2 == 3) {
            return new A0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final String n() {
        return this.zze;
    }
}
