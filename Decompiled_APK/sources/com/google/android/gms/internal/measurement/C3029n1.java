package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.n1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3029n1 extends W1 {
    private static final C3029n1 zzb;
    private int zzd;
    private String zze = "";
    private InterfaceC2975c2 zzf = C3059t2.e;

    static {
        C3029n1 c3029n1 = new C3029n1();
        zzb = c3029n1;
        W1.j(C3029n1.class, c3029n1);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001ဈ\u0000\u0002\u001b", new Object[]{"zzd", "zze", "zzf", C3039p1.class});
        }
        if (i2 == 3) {
            return new C3029n1();
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

    public final InterfaceC2975c2 o() {
        return this.zzf;
    }
}
