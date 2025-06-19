package com.google.android.gms.internal.measurement;

/* renamed from: com.google.android.gms.internal.measurement.o1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3034o1 extends W1 {
    private static final C3034o1 zzb;
    private int zzd;
    private InterfaceC2975c2 zze = C3059t2.e;
    private C3024m1 zzf;

    static {
        C3034o1 c3034o1 = new C3034o1();
        zzb = c3034o1;
        W1.j(C3034o1.class, c3034o1);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u001b\u0002ဉ\u0000", new Object[]{"zzd", "zze", C3039p1.class, "zzf"});
        }
        if (i2 == 3) {
            return new C3034o1();
        }
        if (i2 == 4) {
            return new C3043q0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final C3024m1 n() {
        C3024m1 c3024m1 = this.zzf;
        return c3024m1 == null ? C3024m1.o() : c3024m1;
    }

    public final InterfaceC2975c2 o() {
        return this.zze;
    }
}
