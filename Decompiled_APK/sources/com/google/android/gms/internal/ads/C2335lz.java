package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.lz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2335lz extends OA {
    private static final C2335lz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private BA zzd = BA.b;

    static {
        C2335lz c2335lz = new C2335lz();
        zza = c2335lz;
        OA.k(C2335lz.class, c2335lz);
    }

    public static InterfaceC2219jB A() {
        return zza.h();
    }

    public static C2292kz x() {
        return (C2292kz) zza.g();
    }

    public static C2335lz y(BA ba, IA ia) {
        return (C2335lz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0001\u0003\u0002\u0000\u0000\u0000\u0001\u000b\u0003\n", new Object[]{"zzc", "zzd"});
        }
        if (iK == 3) {
            return new C2335lz();
        }
        if (iK == 4) {
            return new C2292kz(zza);
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
        synchronized (C2335lz.class) {
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

    public final BA z() {
        return this.zzd;
    }
}
