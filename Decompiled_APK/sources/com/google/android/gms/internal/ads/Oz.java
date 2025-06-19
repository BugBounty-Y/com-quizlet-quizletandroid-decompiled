package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Oz extends OA {
    private static final Oz zza;
    private static volatile InterfaceC2219jB zzb;
    private String zzc = "";
    private int zzd;
    private int zze;
    private int zzf;

    static {
        Oz oz = new Oz();
        zza = oz;
        OA.k(Oz.class, oz);
    }

    public static void A(Oz oz, int i) {
        if (i == 1) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        oz.zzd = i - 2;
    }

    public static Nz w() {
        return (Nz) zza.g();
    }

    public static /* synthetic */ void z(Oz oz, String str) {
        str.getClass();
        oz.zzc = str;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0004\u0000\u0000\u0001\u0004\u0004\u0000\u0000\u0000\u0001Ȉ\u0002\f\u0003\u000b\u0004\f", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new Oz();
        }
        if (iK == 4) {
            return new Nz(zza);
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
        synchronized (Oz.class) {
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
