package com.google.android.gms.internal.measurement;

import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.n0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3028n0 extends W1 {
    private static final C3028n0 zzb;
    private int zzd;
    private int zze;
    private String zzf = "";
    private InterfaceC2975c2 zzg = C3059t2.e;
    private boolean zzh;
    private C3052s0 zzi;
    private boolean zzj;
    private boolean zzk;
    private boolean zzl;

    static {
        C3028n0 c3028n0 = new C3028n0();
        zzb = c3028n0;
        W1.j(C3028n0.class, c3028n0);
    }

    public static C3023m0 p() {
        return (C3023m0) zzb.e();
    }

    public static /* synthetic */ void u(C3028n0 c3028n0, String str) {
        c3028n0.zzd |= 2;
        c3028n0.zzf = str;
    }

    public static void v(C3028n0 c3028n0, int i, C3038p0 c3038p0) {
        InterfaceC2975c2 interfaceC2975c2 = c3028n0.zzg;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c3028n0.zzg = interfaceC2975c2.f(size + size);
        }
        c3028n0.zzg.set(i, c3038p0);
    }

    public final boolean A() {
        return (this.zzd & 1) != 0;
    }

    public final boolean B() {
        return (this.zzd & 64) != 0;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\b\u0000\u0001\u0001\b\b\u0000\u0001\u0000\u0001င\u0000\u0002ဈ\u0001\u0003\u001b\u0004ဇ\u0002\u0005ဉ\u0003\u0006ဇ\u0004\u0007ဇ\u0005\bဇ\u0006", new Object[]{"zzd", "zze", "zzf", "zzg", C3038p0.class, "zzh", "zzi", "zzj", "zzk", "zzl"});
        }
        if (i2 == 3) {
            return new C3028n0();
        }
        if (i2 == 4) {
            return new C3023m0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzg.size();
    }

    public final int o() {
        return this.zze;
    }

    public final C3038p0 q(int i) {
        return (C3038p0) this.zzg.get(i);
    }

    public final C3052s0 r() {
        C3052s0 c3052s0 = this.zzi;
        return c3052s0 == null ? C3052s0.n() : c3052s0;
    }

    public final String s() {
        return this.zzf;
    }

    public final List t() {
        return this.zzg;
    }

    public final boolean w() {
        return this.zzj;
    }

    public final boolean x() {
        return this.zzk;
    }

    public final boolean y() {
        return this.zzl;
    }

    public final boolean z() {
        return (this.zzd & 8) != 0;
    }
}
