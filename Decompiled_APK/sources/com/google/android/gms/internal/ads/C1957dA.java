package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.dA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1957dA extends OA {
    private static final C1957dA zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private C2088gA zze;

    static {
        C1957dA c1957dA = new C1957dA();
        zza = c1957dA;
        OA.k(C1957dA.class, c1957dA);
    }

    public static /* synthetic */ void A(C1957dA c1957dA, C2088gA c2088gA) {
        c1957dA.zze = c2088gA;
        c1957dA.zzc |= 1;
    }

    public static C1913cA x() {
        return (C1913cA) zza.g();
    }

    public static C1957dA y(BA ba, IA ia) {
        return (C1957dA) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0003\u0002\u0000\u0000\u0000\u0001\u000b\u0003ဉ\u0000", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new C1957dA();
        }
        if (iK == 4) {
            return new C1913cA(zza);
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
        synchronized (C1957dA.class) {
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
