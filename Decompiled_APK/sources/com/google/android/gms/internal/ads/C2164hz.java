package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.hz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2164hz extends OA {
    private static final C2164hz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private C2249jz zzd;
    private int zze;

    static {
        C2164hz c2164hz = new C2164hz();
        zza = c2164hz;
        OA.k(C2164hz.class, c2164hz);
    }

    public static /* synthetic */ void B(C2164hz c2164hz, C2249jz c2249jz) {
        c2164hz.zzd = c2249jz;
        c2164hz.zzc |= 1;
    }

    public static C2120gz x() {
        return (C2120gz) zza.g();
    }

    public static C2164hz y(BA ba, IA ia) {
        return (C2164hz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဉ\u0000\u0002\u000b", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new C2164hz();
        }
        if (iK == 4) {
            return new C2120gz(zza);
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
        synchronized (C2164hz.class) {
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
        return this.zze;
    }

    public final C2249jz z() {
        C2249jz c2249jz = this.zzd;
        return c2249jz == null ? C2249jz.y() : c2249jz;
    }
}
