package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.g7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2085g7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    private static final C2085g7 zzf;
    private static volatile InterfaceC2219jB zzg;
    private int zzh;
    private String zzi = "";
    private VA zzj = C2348mB.e;
    private int zzk = 1000;
    private int zzl = 1000;
    private int zzm = 1000;

    static {
        C2085g7 c2085g7 = new C2085g7();
        zzf = c2085g7;
        OA.k(C2085g7.class, c2085g7);
    }

    public static void w(C2085g7 c2085g7, String str) {
        c2085g7.getClass();
        str.getClass();
        c2085g7.zzh |= 1;
        c2085g7.zzi = str;
    }

    public static C2085g7 x() {
        return zzf;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            U3 u3 = U3.t;
            return new C2391nB(zzf, "\u0004\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0001\u0000\u0001ဈ\u0000\u0002\u001b\u0003᠌\u0001\u0004᠌\u0002\u0005᠌\u0003", new Object[]{"zzh", "zzi", "zzj", C1910c7.class, "zzk", u3, "zzl", u3, "zzm", u3});
        }
        if (iK == 3) {
            return new C2085g7();
        }
        if (iK == 4) {
            return new C2041f7(zzf);
        }
        if (iK == 5) {
            return zzf;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzg;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2085g7.class) {
            try {
                na = zzg;
                if (na == null) {
                    na = new NA();
                    zzg = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
