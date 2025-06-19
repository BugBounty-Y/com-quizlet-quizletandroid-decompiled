package com.google.android.gms.internal.measurement;

import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.internal.measurement.a1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2964a1 extends W1 {
    private static final C2964a1 zzb;
    private int zzd;
    private InterfaceC2975c2 zze = C3059t2.e;
    private String zzf = "";
    private String zzg = "";
    private int zzh;

    static {
        C2964a1 c2964a1 = new C2964a1();
        zzb = c2964a1;
        W1.j(C2964a1.class, c2964a1);
    }

    public static Z0 o() {
        return (Z0) zzb.e();
    }

    public static Z0 p(C2964a1 c2964a1) {
        V1 v1E = zzb.e();
        v1E.d(c2964a1);
        return (Z0) v1E;
    }

    public static /* synthetic */ void u(C2964a1 c2964a1, ArrayList arrayList) {
        c2964a1.C();
        J1.b(arrayList, c2964a1.zze);
    }

    public static /* synthetic */ void v(C2964a1 c2964a1, C2974c1 c2974c1) {
        c2964a1.C();
        c2964a1.zze.add(c2974c1);
    }

    public static void w(C2964a1 c2964a1) {
        c2964a1.zze = C3059t2.e;
    }

    public static /* synthetic */ void x(C2964a1 c2964a1, int i, C2974c1 c2974c1) {
        c2964a1.C();
        c2964a1.zze.set(i, c2974c1);
    }

    public static /* synthetic */ void y(C2964a1 c2964a1, String str) {
        str.getClass();
        c2964a1.zzd |= 1;
        c2964a1.zzf = str;
    }

    public static /* synthetic */ void z(C2964a1 c2964a1, String str) {
        str.getClass();
        c2964a1.zzd |= 2;
        c2964a1.zzg = str;
    }

    public final boolean A() {
        return (this.zzd & 1) != 0;
    }

    public final boolean B() {
        return (this.zzd & 2) != 0;
    }

    public final void C() {
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
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0001\u0001\t\u0004\u0000\u0001\u0000\u0001\u001b\u0007ဈ\u0000\bဈ\u0001\t᠌\u0002", new Object[]{"zzd", "zze", C2974c1.class, "zzf", "zzg", "zzh", C3047r0.g});
        }
        if (i2 == 3) {
            return new C2964a1();
        }
        if (i2 == 4) {
            return new Z0(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zze.size();
    }

    public final C2974c1 q(int i) {
        return (C2974c1) this.zze.get(i);
    }

    public final String r() {
        return this.zzf;
    }

    public final String s() {
        return this.zzg;
    }

    public final List t() {
        return this.zze;
    }
}
