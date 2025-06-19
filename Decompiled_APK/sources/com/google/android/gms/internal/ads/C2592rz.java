package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.rz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2592rz extends OA {
    private static final C2592rz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;

    static {
        C2592rz c2592rz = new C2592rz();
        zza = c2592rz;
        OA.k(C2592rz.class, c2592rz);
    }

    public static C2550qz y() {
        return (C2550qz) zza.g();
    }

    public static C2592rz z(BA ba, IA ia) {
        return (C2592rz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0000\u0000\u0001\u000b\u0002\u000b", new Object[]{"zzd", "zzc"});
        }
        if (iK == 3) {
            return new C2592rz();
        }
        if (iK == 4) {
            return new C2550qz(zza);
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
        synchronized (C2592rz.class) {
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

    public final int x() {
        return this.zzd;
    }
}
