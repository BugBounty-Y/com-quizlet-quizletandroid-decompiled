package com.google.android.gms.internal.measurement;

import java.util.ArrayList;
import java.util.List;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.measurement.f1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2989f1 extends W1 {
    private static final C2989f1 zzb;
    private InterfaceC2970b2 zzd;
    private InterfaceC2970b2 zze;
    private InterfaceC2975c2 zzf;
    private InterfaceC2975c2 zzg;

    static {
        C2989f1 c2989f1 = new C2989f1();
        zzb = c2989f1;
        W1.j(C2989f1.class, c2989f1);
    }

    public C2989f1() {
        C3000h2 c3000h2 = C3000h2.e;
        this.zzd = c3000h2;
        this.zze = c3000h2;
        C3059t2 c3059t2 = C3059t2.e;
        this.zzf = c3059t2;
        this.zzg = c3059t2;
    }

    public static void A(C2989f1 c2989f1, List list) {
        RandomAccess randomAccess = c2989f1.zzd;
        if (!((K1) randomAccess).a) {
            C3000h2 c3000h2 = (C3000h2) randomAccess;
            int i = c3000h2.c;
            c2989f1.zzd = c3000h2.f(i + i);
        }
        J1.b(list, c2989f1.zzd);
    }

    public static void B(C2989f1 c2989f1) {
        c2989f1.zzf = C3059t2.e;
    }

    public static void C(C2989f1 c2989f1) {
        c2989f1.zze = C3000h2.e;
    }

    public static void D(C2989f1 c2989f1) {
        c2989f1.zzg = C3059t2.e;
    }

    public static void E(C2989f1 c2989f1) {
        c2989f1.zzd = C3000h2.e;
    }

    public static C2984e1 r() {
        return (C2984e1) zzb.e();
    }

    public static C2989f1 s() {
        return zzb;
    }

    public static void x(C2989f1 c2989f1, ArrayList arrayList) {
        InterfaceC2975c2 interfaceC2975c2 = c2989f1.zzf;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c2989f1.zzf = interfaceC2975c2.f(size + size);
        }
        J1.b(arrayList, c2989f1.zzf);
    }

    public static void y(C2989f1 c2989f1, List list) {
        RandomAccess randomAccess = c2989f1.zze;
        if (!((K1) randomAccess).a) {
            C3000h2 c3000h2 = (C3000h2) randomAccess;
            int i = c3000h2.c;
            c2989f1.zze = c3000h2.f(i + i);
        }
        J1.b(list, c2989f1.zze);
    }

    public static void z(C2989f1 c2989f1, List list) {
        InterfaceC2975c2 interfaceC2975c2 = c2989f1.zzg;
        if (!((K1) interfaceC2975c2).a) {
            int size = interfaceC2975c2.size();
            c2989f1.zzg = interfaceC2975c2.f(size + size);
        }
        J1.b(list, c2989f1.zzg);
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0004\u0000\u0000\u0001\u0004\u0004\u0000\u0004\u0000\u0001\u0015\u0002\u0015\u0003\u001b\u0004\u001b", new Object[]{"zzd", "zze", "zzf", S0.class, "zzg", C2999h1.class});
        }
        if (i2 == 3) {
            return new C2989f1();
        }
        if (i2 == 4) {
            return new C2984e1(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return this.zzf.size();
    }

    public final int o() {
        return ((C3000h2) this.zze).size();
    }

    public final int p() {
        return this.zzg.size();
    }

    public final int q() {
        return ((C3000h2) this.zzd).size();
    }

    public final List t() {
        return this.zzf;
    }

    public final List u() {
        return this.zze;
    }

    public final List v() {
        return this.zzg;
    }

    public final InterfaceC2970b2 w() {
        return this.zzd;
    }
}
