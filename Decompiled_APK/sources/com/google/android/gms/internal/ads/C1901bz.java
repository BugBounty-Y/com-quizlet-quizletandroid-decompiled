package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.bz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1901bz extends OA {
    private static final C1901bz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private C1988dz zzd;
    private int zze;

    static {
        C1901bz c1901bz = new C1901bz();
        zza = c1901bz;
        OA.k(C1901bz.class, c1901bz);
    }

    public static /* synthetic */ void B(C1901bz c1901bz, C1988dz c1988dz) {
        c1901bz.zzd = c1988dz;
        c1901bz.zzc |= 1;
    }

    public static C1858az x() {
        return (C1858az) zza.g();
    }

    public static C1901bz y() {
        return zza;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဉ\u0000\u0002\u000b", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new C1901bz();
        }
        if (iK == 4) {
            return new C1858az(zza);
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
        synchronized (C1901bz.class) {
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

    public final C1988dz z() {
        C1988dz c1988dz = this.zzd;
        return c1988dz == null ? C1988dz.y() : c1988dz;
    }
}
