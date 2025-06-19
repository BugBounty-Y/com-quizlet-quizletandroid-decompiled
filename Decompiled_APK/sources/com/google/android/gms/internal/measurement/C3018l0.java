package com.google.android.gms.internal.measurement;

import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.l0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3018l0 extends W1 {
    private static final C3018l0 zzb;
    private int zzd;
    private int zze;
    private InterfaceC2975c2 zzf;
    private InterfaceC2975c2 zzg;
    private boolean zzh;
    private boolean zzi;

    static {
        C3018l0 c3018l0 = new C3018l0();
        zzb = c3018l0;
        W1.j(C3018l0.class, c3018l0);
    }

    public C3018l0() {
        C3059t2 c3059t2 = C3059t2.e;
        this.zzf = c3059t2;
        this.zzg = c3059t2;
    }

    public static void u(C3018l0 c3018l0, int i, C3028n0 c3028n0) {
        InterfaceC2975c2 interfaceC2975c2 = c3018l0.zzg;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c3018l0.zzg = interfaceC2975c2.f(size + size);
        }
        c3018l0.zzg.set(i, c3028n0);
    }

    public static void v(C3018l0 c3018l0, int i, C3062u0 c3062u0) {
        InterfaceC2975c2 interfaceC2975c2 = c3018l0.zzf;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c3018l0.zzf = interfaceC2975c2.f(size + size);
        }
        c3018l0.zzf.set(i, c3062u0);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0002\u0000\u0001င\u0000\u0002\u001b\u0003\u001b\u0004ဇ\u0001\u0005ဇ\u0002", new Object[]{"zzd", "zze", "zzf", C3062u0.class, "zzg", C3028n0.class, "zzh", "zzi"});
        }
        if (i2 == 3) {
            return new C3018l0();
        }
        if (i2 == 4) {
            return new C3013k0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zze;
    }

    public final int o() {
        return this.zzg.size();
    }

    public final int p() {
        return this.zzf.size();
    }

    public final C3028n0 q(int i) {
        return (C3028n0) this.zzg.get(i);
    }

    public final C3062u0 r(int i) {
        return (C3062u0) this.zzf.get(i);
    }

    public final List s() {
        return this.zzg;
    }

    public final List t() {
        return this.zzf;
    }

    public final boolean w() {
        return (this.zzd & 1) != 0;
    }
}
