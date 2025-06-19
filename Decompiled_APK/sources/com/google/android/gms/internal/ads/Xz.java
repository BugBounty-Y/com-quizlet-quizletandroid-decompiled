package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Xz extends OA {
    private static final Xz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private String zzd = "";
    private Gz zze;

    static {
        Xz xz = new Xz();
        zza = xz;
        OA.k(Xz.class, xz);
    }

    public static /* synthetic */ void B(Xz xz, Gz gz) {
        gz.getClass();
        xz.zze = gz;
        xz.zzc |= 1;
    }

    public static /* synthetic */ void C(Xz xz, String str) {
        str.getClass();
        xz.zzd = str;
    }

    public static Wz x() {
        return (Wz) zza.g();
    }

    public static Xz y() {
        return zza;
    }

    public static Xz z(BA ba, IA ia) {
        return (Xz) OA.o(zza, ba, ia);
    }

    public final String A() {
        return this.zzd;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001Ȉ\u0002ဉ\u0000", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new Xz();
        }
        if (iK == 4) {
            return new Wz(zza);
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
        synchronized (Xz.class) {
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

    public final Gz w() {
        Gz gz = this.zze;
        return gz == null ? Gz.x() : gz;
    }
}
