package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.kC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2263kC extends OA {
    private static final C2263kC zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private long zze;
    private boolean zzf;
    private int zzg;
    private boolean zzj;
    private boolean zzk;
    private String zzd = "";
    private String zzh = "";
    private String zzi = "";

    static {
        C2263kC c2263kC = new C2263kC();
        zza = c2263kC;
        OA.k(C2263kC.class, c2263kC);
    }

    public static C2220jC w() {
        return (C2220jC) zza.g();
    }

    public static /* synthetic */ void x(C2263kC c2263kC, String str) {
        c2263kC.zzc |= 1;
        c2263kC.zzd = str;
    }

    public static /* synthetic */ void y(C2263kC c2263kC, long j) {
        c2263kC.zzc |= 2;
        c2263kC.zze = j;
    }

    public static /* synthetic */ void z(C2263kC c2263kC, boolean z) {
        c2263kC.zzc |= 4;
        c2263kC.zzf = z;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\b\u0000\u0001\u0001\b\b\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဂ\u0001\u0003ဇ\u0002\u0004᠌\u0003\u0005ဈ\u0004\u0006ဈ\u0005\u0007ဇ\u0006\bဇ\u0007", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", C1828aC.g, "zzh", "zzi", "zzj", "zzk"});
        }
        if (iK == 3) {
            return new C2263kC();
        }
        if (iK == 4) {
            return new C2220jC(zza);
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
        synchronized (C2263kC.class) {
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
