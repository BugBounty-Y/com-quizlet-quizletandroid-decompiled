package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.gC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2090gC extends OA {
    private static final C2090gC zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private String zze = "";
    private BA zzf;
    private BA zzg;

    static {
        C2090gC c2090gC = new C2090gC();
        zza = c2090gC;
        OA.k(C2090gC.class, c2090gC);
    }

    public C2090gC() {
        C2905zA c2905zA = BA.b;
        this.zzf = c2905zA;
        this.zzg = c2905zA;
    }

    public static C2002eC w() {
        return (C2002eC) zza.g();
    }

    public static /* synthetic */ void x(C2090gC c2090gC, BA ba) {
        ba.getClass();
        c2090gC.zzc |= 4;
        c2090gC.zzf = ba;
    }

    public static /* synthetic */ void y(C2090gC c2090gC) {
        c2090gC.zzc |= 2;
        c2090gC.zze = "image/png";
    }

    public static /* synthetic */ void z(C2090gC c2090gC) {
        c2090gC.zzd = 1;
        c2090gC.zzc = 1 | c2090gC.zzc;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001᠌\u0000\u0002ဈ\u0001\u0003ည\u0002\u0004ည\u0003", new Object[]{"zzc", "zzd", C1828aC.d, "zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new C2090gC();
        }
        if (iK == 4) {
            return new C2002eC(zza);
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
        synchronized (C2090gC.class) {
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
