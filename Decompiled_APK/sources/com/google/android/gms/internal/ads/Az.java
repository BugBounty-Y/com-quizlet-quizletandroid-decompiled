package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Az extends OA {
    private static final Az zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private Cz zzd;
    private int zze;
    private int zzf;

    static {
        Az az = new Az();
        zza = az;
        OA.k(Az.class, az);
    }

    public static Az A(BA ba, IA ia) {
        return (Az) OA.o(zza, ba, ia);
    }

    public static /* synthetic */ void D(Az az, Cz cz) {
        az.zzd = cz;
        az.zzc |= 1;
    }

    public static C2936zz y() {
        return (C2936zz) zza.g();
    }

    public static Az z() {
        return zza;
    }

    public final Cz B() {
        Cz cz = this.zzd;
        return cz == null ? Cz.z() : cz;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဉ\u0000\u0002\u000b\u0003\u000b", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new Az();
        }
        if (iK == 4) {
            return new C2936zz(zza);
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
        synchronized (Az.class) {
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
        return this.zze;
    }

    public final int x() {
        return this.zzf;
    }
}
