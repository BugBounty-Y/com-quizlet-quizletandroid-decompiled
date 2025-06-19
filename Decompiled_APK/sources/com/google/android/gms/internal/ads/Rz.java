package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Rz extends OA {
    private static final Rz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private Tz zze;

    static {
        Rz rz = new Rz();
        zza = rz;
        OA.k(Rz.class, rz);
    }

    public static InterfaceC2219jB A() {
        return zza.h();
    }

    public static /* synthetic */ void B(Rz rz, Tz tz) {
        rz.zze = tz;
        rz.zzc |= 1;
    }

    public static Qz x() {
        return (Qz) zza.g();
    }

    public static Rz y(BA ba, IA ia) {
        return (Rz) OA.o(zza, ba, ia);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001\u000b\u0002ဉ\u0000", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new Rz();
        }
        if (iK == 4) {
            return new Qz(zza);
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
        synchronized (Rz.class) {
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
        return this.zzd;
    }

    public final Tz z() {
        Tz tz = this.zze;
        return tz == null ? Tz.x() : tz;
    }
}
