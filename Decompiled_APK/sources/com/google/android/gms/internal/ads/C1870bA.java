package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.bA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1870bA extends OA {
    private static final C1870bA zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private C2088gA zze;
    private BA zzf = BA.b;

    static {
        C1870bA c1870bA = new C1870bA();
        zza = c1870bA;
        OA.k(C1870bA.class, c1870bA);
    }

    public static /* synthetic */ void C(C1870bA c1870bA, C2088gA c2088gA) {
        c1870bA.zze = c2088gA;
        c1870bA.zzc |= 1;
    }

    public static C1826aA x() {
        return (C1826aA) zza.g();
    }

    public static C1870bA y(BA ba, IA ia) {
        return (C1870bA) OA.o(zza, ba, ia);
    }

    public final BA A() {
        return this.zzf;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u000b\u0002ဉ\u0000\u0003\n", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new C1870bA();
        }
        if (iK == 4) {
            return new C1826aA(zza);
        }
        if (iK == 5) {
            return zza;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzb;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C1870bA.class) {
            try {
                na = zzb;
                if (na == null) {
                    na = new NA();
                    zzb = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }

    public final int w() {
        return this.zzd;
    }

    public final C2088gA z() {
        C2088gA c2088gA = this.zze;
        return c2088gA == null ? C2088gA.y() : c2088gA;
    }
}
