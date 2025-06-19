package com.google.android.gms.internal.measurement;

import java.util.List;

/* loaded from: classes2.dex */
public final class U0 extends W1 {
    private static final U0 zzb;
    private int zzd;
    private InterfaceC2975c2 zze = C3059t2.e;
    private String zzf = "";
    private long zzg;
    private long zzh;
    private int zzi;

    static {
        U0 u0 = new U0();
        zzb = u0;
        W1.j(U0.class, u0);
    }

    public static /* synthetic */ void A(U0 u0, int i, X0 x0) {
        u0.G();
        u0.zze.set(i, x0);
    }

    public static /* synthetic */ void B(long j, U0 u0) {
        u0.zzd |= 4;
        u0.zzh = j;
    }

    public static /* synthetic */ void C(long j, U0 u0) {
        u0.zzd |= 2;
        u0.zzg = j;
    }

    public static T0 r() {
        return (T0) zzb.e();
    }

    public static /* synthetic */ void v(U0 u0, Iterable iterable) {
        u0.G();
        J1.b(iterable, u0.zze);
    }

    public static /* synthetic */ void w(U0 u0, X0 x0) {
        x0.getClass();
        u0.G();
        u0.zze.add(x0);
    }

    public static void x(U0 u0) {
        u0.zze = C3059t2.e;
    }

    public static /* synthetic */ void y(U0 u0, int i) {
        u0.G();
        u0.zze.remove(i);
    }

    public static /* synthetic */ void z(U0 u0, String str) {
        str.getClass();
        u0.zzd |= 1;
        u0.zzf = str;
    }

    public final boolean D() {
        return (this.zzd & 8) != 0;
    }

    public final boolean E() {
        return (this.zzd & 4) != 0;
    }

    public final boolean F() {
        return (this.zzd & 2) != 0;
    }

    public final void G() {
        InterfaceC2975c2 interfaceC2975c2 = this.zze;
        if (((K1) interfaceC2975c2).a) {
            return;
        }
        int size = interfaceC2975c2.size();
        this.zze = interfaceC2975c2.f(size + size);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0001\u0000\u0001\u001b\u0002ဈ\u0000\u0003ဂ\u0001\u0004ဂ\u0002\u0005င\u0003", new Object[]{"zzd", "zze", X0.class, "zzf", "zzg", "zzh", "zzi"});
        }
        if (i2 == 3) {
            return new U0();
        }
        if (i2 == 4) {
            return new T0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzi;
    }

    public final int o() {
        return this.zze.size();
    }

    public final long p() {
        return this.zzh;
    }

    public final long q() {
        return this.zzg;
    }

    public final X0 s(int i) {
        return (X0) this.zze.get(i);
    }

    public final String t() {
        return this.zzf;
    }

    public final List u() {
        return this.zze;
    }
}
