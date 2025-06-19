package com.google.android.gms.internal.measurement;

/* loaded from: classes2.dex */
public final class F0 extends W1 {
    private static final F0 zzb;
    private InterfaceC2975c2 zzd = C3059t2.e;

    static {
        F0 f0 = new F0();
        zzb = f0;
        W1.j(F0.class, f0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0001\u0000\u0001\u001a", new Object[]{"zzd"});
        }
        if (i2 == 3) {
            return new F0();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }
}
