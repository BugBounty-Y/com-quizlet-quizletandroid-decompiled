package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.n7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2387n7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    private static final C2387n7 zze;
    private static volatile InterfaceC2219jB zzf;
    private int zzg;
    private int zzi;
    private F6 zzk;
    private String zzh = "";
    private SA zzj = PA.e;

    static {
        C2387n7 c2387n7 = new C2387n7();
        zze = c2387n7;
        OA.k(C2387n7.class, c2387n7);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zze, "\u0004\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0000\u0001ဈ\u0000\u0002᠌\u0001\u0003\u0016\u0004ဉ\u0002", new Object[]{"zzg", "zzh", "zzi", U3.t, "zzj", "zzk"});
        }
        if (iK == 3) {
            return new C2387n7();
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
        synchronized (C2387n7.class) {
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
