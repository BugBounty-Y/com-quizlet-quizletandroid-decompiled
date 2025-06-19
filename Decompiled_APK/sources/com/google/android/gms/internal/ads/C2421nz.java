package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.nz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2421nz extends OA {
    private static final C2421nz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;

    static {
        C2421nz c2421nz = new C2421nz();
        zza = c2421nz;
        OA.k(C2421nz.class, c2421nz);
    }

    public static C2378mz y() {
        return (C2378mz) zza.g();
    }

    public static C2421nz z(BA ba, IA ia) {
        return (C2421nz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0002\u0003\u0002\u0000\u0000\u0000\u0002\u000b\u0003\u000b", new Object[]{"zzc", "zzd"});
        }
        if (iK == 3) {
            return new C2421nz();
        }
        if (iK == 4) {
            return new C2378mz(zza);
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
        synchronized (C2421nz.class) {
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
