package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.k7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2258k7 extends OA {
    public static final int zza = 5;
    public static final int zzb = 6;
    public static final int zzc = 7;
    public static final int zzd = 8;
    private static final C2258k7 zze;
    private static volatile InterfaceC2219jB zzf;
    private int zzg;
    private int zzh;
    private H6 zzi;
    private String zzj = "";
    private String zzk = "";

    static {
        C2258k7 c2258k7 = new C2258k7();
        zze = c2258k7;
        OA.k(C2258k7.class, c2258k7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zze, "\u0004\u0004\u0000\u0001\u0005\b\u0004\u0000\u0000\u0000\u0005᠌\u0000\u0006ဉ\u0001\u0007ဈ\u0002\bဈ\u0003", new Object[]{"zzg", "zzh", U3.s, "zzi", "zzj", "zzk"});
        }
        if (iK == 3) {
            return new C2258k7();
        }
        if (iK == 4) {
            return new C1954d7(zze);
        }
        if (iK == 5) {
            return zze;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzf;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2258k7.class) {
            try {
                na = zzf;
                if (na == null) {
                    na = new NA();
                    zzf = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
