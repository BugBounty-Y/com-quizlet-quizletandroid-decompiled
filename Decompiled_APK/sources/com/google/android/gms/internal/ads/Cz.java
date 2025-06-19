package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Cz extends OA {
    private static final Cz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;

    static {
        Cz cz = new Cz();
        zza = cz;
        OA.k(Cz.class, cz);
    }

    public static Bz y() {
        return (Bz) zza.g();
    }

    public static Cz z() {
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
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0000\u0000\u0001\f\u0002\u000b", new Object[]{"zzc", "zzd"});
        }
        if (iK == 3) {
            return new Cz();
        }
        if (iK == 4) {
            return new Bz(zza);
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
        synchronized (Cz.class) {
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

    public final EnumC2764vz x() {
        int i = this.zzc;
        EnumC2764vz enumC2764vz = i != 0 ? i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? null : EnumC2764vz.SHA224 : EnumC2764vz.SHA512 : EnumC2764vz.SHA256 : EnumC2764vz.SHA384 : EnumC2764vz.SHA1 : EnumC2764vz.UNKNOWN_HASH;
        return enumC2764vz == null ? EnumC2764vz.UNRECOGNIZED : enumC2764vz;
    }
}
