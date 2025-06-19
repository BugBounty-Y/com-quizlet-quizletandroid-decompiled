package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.j7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2215j7 extends OA {
    public static final int zza = 1;
    public static final int zzb = 2;
    public static final int zzc = 3;
    public static final int zzd = 4;
    public static final int zze = 5;
    public static final int zzf = 6;
    public static final int zzg = 7;
    public static final int zzh = 8;
    private static final C2215j7 zzi;
    private static volatile InterfaceC2219jB zzj;
    private int zzk;
    private F6 zzm;
    private int zzn;
    private H6 zzo;
    private int zzp;
    private String zzl = "";
    private int zzu = 1000;
    private int zzv = 1000;
    private int zzw = 1000;

    static {
        C2215j7 c2215j7 = new C2215j7();
        zzi = c2215j7;
        OA.k(C2215j7.class, c2215j7);
    }

    public static void w(C2215j7 c2215j7, String str) {
        c2215j7.getClass();
        c2215j7.zzk |= 1;
        c2215j7.zzl = str;
    }

    public static void x(C2215j7 c2215j7, H6 h6) {
        c2215j7.getClass();
        c2215j7.zzo = h6;
        c2215j7.zzk |= 8;
    }

    public static C2215j7 y() {
        return zzi;
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
            return new C2391nB(zzi, "\u0004\b\u0000\u0001\u0001\b\b\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဉ\u0001\u0003င\u0002\u0004ဉ\u0003\u0005င\u0004\u0006᠌\u0005\u0007᠌\u0006\b᠌\u0007", new Object[]{"zzk", "zzl", "zzm", "zzn", "zzo", "zzp", "zzu", u3, "zzv", u3, "zzw", u3});
        }
        if (iK == 3) {
            return new C2215j7();
        }
        if (iK == 4) {
            return new C2173i7(zzi);
        }
        if (iK == 5) {
            return zzi;
        }
        if (iK != 6) {
            throw null;
        }
        InterfaceC2219jB interfaceC2219jB = zzj;
        if (interfaceC2219jB != null) {
            return interfaceC2219jB;
        }
        synchronized (C2215j7.class) {
            try {
                na = zzj;
                if (na == null) {
                    na = new NA();
                    zzj = na;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return na;
    }
}
