package com.google.android.gms.internal.measurement;

import java.util.List;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.measurement.h1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2999h1 extends W1 {
    private static final C2999h1 zzb;
    private int zzd;
    private int zze;
    private InterfaceC2970b2 zzf = C3000h2.e;

    static {
        C2999h1 c2999h1 = new C2999h1();
        zzb = c2999h1;
        W1.j(C2999h1.class, c2999h1);
    }

    public static C2994g1 q() {
        return (C2994g1) zzb.e();
    }

    public static void s(C2999h1 c2999h1, List list) {
        RandomAccess randomAccess = c2999h1.zzf;
        if (!((K1) randomAccess).a) {
            C3000h2 c3000h2 = (C3000h2) randomAccess;
            int i = c3000h2.c;
            c2999h1.zzf = c3000h2.f(i + i);
        }
        J1.b(list, c2999h1.zzf);
    }

    public static /* synthetic */ void t(C2999h1 c2999h1, int i) {
        c2999h1.zzd |= 1;
        c2999h1.zze = i;
    }

    @Override // com.google.android.gms.internal.measurement.W1
    public final Object m(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3064u2(zzb, "\u0004\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001င\u0000\u0002\u0014", new Object[]{"zzd", "zze", "zzf"});
        }
        if (i2 == 3) {
            return new C2999h1();
        }
        if (i2 == 4) {
            return new C2994g1(zzb);
        }
        if (i2 == 5) {
            return zzb;
        }
        throw null;
    }

    public final int n() {
        return ((C3000h2) this.zzf).size();
    }

    public final int o() {
        return this.zze;
    }

    public final long p(int i) {
        return ((C3000h2) this.zzf).b(i);
    }

    public final List r() {
        return this.zzf;
    }

    public final boolean u() {
        return (this.zzd & 1) != 0;
    }
}
