package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Ry extends OA {
    private static final Ry zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private Ty zze;

    static {
        Ry ry = new Ry();
        zza = ry;
        OA.k(Ry.class, ry);
    }

    public static /* synthetic */ void B(Ry ry, Ty ty) {
        ry.zze = ty;
        ry.zzc |= 1;
    }

    public static Qy x() {
        return (Qy) zza.g();
    }

    public static Ry y(BA ba, IA ia) {
        return (Ry) OA.o(zza, ba, ia);
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
            return new Ry();
        }
        if (iK == 4) {
            return new Qy(zza);
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
        synchronized (Ry.class) {
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

    public final Ty z() {
        Ty ty = this.zze;
        return ty == null ? Ty.y() : ty;
    }
}
