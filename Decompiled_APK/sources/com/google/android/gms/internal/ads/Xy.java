package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Xy extends OA {
    private static final Xy zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private C1901bz zzd;
    private Az zze;

    static {
        Xy xy = new Xy();
        zza = xy;
        OA.k(Xy.class, xy);
    }

    public static /* synthetic */ void A(Xy xy, C1901bz c1901bz) {
        xy.zzd = c1901bz;
        xy.zzc |= 1;
    }

    public static /* synthetic */ void B(Xy xy, Az az) {
        xy.zze = az;
        xy.zzc |= 2;
    }

    public static Wy w() {
        return (Wy) zza.g();
    }

    public static Xy x(BA ba, IA ia) {
        return (Xy) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဉ\u0000\u0002ဉ\u0001", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new Xy();
        }
        if (iK == 4) {
            return new Wy(zza);
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
        synchronized (Xy.class) {
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

    public final C1901bz y() {
        C1901bz c1901bz = this.zzd;
        return c1901bz == null ? C1901bz.y() : c1901bz;
    }

    public final Az z() {
        Az az = this.zze;
        return az == null ? Az.z() : az;
    }
}
