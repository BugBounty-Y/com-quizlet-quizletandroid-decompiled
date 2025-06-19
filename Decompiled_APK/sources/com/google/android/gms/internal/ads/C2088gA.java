package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.gA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2088gA extends OA {
    private static final C2088gA zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;

    static {
        C2088gA c2088gA = new C2088gA();
        zza = c2088gA;
        OA.k(C2088gA.class, c2088gA);
    }

    public static C2044fA x() {
        return (C2044fA) zza.g();
    }

    public static C2088gA y() {
        return zza;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0001\u0000\u0000\u0001\u0001\u0001\u0000\u0000\u0000\u0001\u000b", new Object[]{"zzc"});
        }
        if (iK == 3) {
            return new C2088gA();
        }
        if (iK == 4) {
            return new C2044fA(zza);
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
        synchronized (C2088gA.class) {
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
        return this.zzc;
    }
}
