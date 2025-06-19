package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.pC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2478pC extends OA {
    private static final C2478pC zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private int zzg;
    private String zze = "";
    private SA zzf = PA.e;
    private VA zzh = C2348mB.e;
    private BA zzi = BA.b;

    static {
        C2478pC c2478pC = new C2478pC();
        zza = c2478pC;
        OA.k(C2478pC.class, c2478pC);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0006\u0000\u0001\u0001\u0007\u0006\u0000\u0002\u0000\u0001င\u0000\u0002ဈ\u0001\u0003\u0016\u0005င\u0002\u0006\u001b\u0007ည\u0003", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", C2435oC.class, "zzi"});
        }
        if (iK == 3) {
            return new C2478pC();
        }
        if (iK == 4) {
            return new XB(zza);
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
        synchronized (C2478pC.class) {
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
}
