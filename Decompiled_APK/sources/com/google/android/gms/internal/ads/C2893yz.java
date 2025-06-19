package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.yz, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2893yz extends OA {
    private static final C2893yz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private Cz zze;
    private BA zzf = BA.b;

    static {
        C2893yz c2893yz = new C2893yz();
        zza = c2893yz;
        OA.k(C2893yz.class, c2893yz);
    }

    public static InterfaceC2219jB C() {
        return zza.h();
    }

    public static /* synthetic */ void E(C2893yz c2893yz, Cz cz) {
        c2893yz.zze = cz;
        c2893yz.zzc |= 1;
    }

    public static C2850xz x() {
        return (C2850xz) zza.g();
    }

    public static C2893yz y() {
        return zza;
    }

    public static C2893yz z(BA ba, IA ia) {
        return (C2893yz) OA.o(zza, ba, ia);
    }

    public final Cz A() {
        Cz cz = this.zze;
        return cz == null ? Cz.z() : cz;
    }

    public final BA B() {
        return this.zzf;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u000b\u0002ဉ\u0000\u0003\n", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new C2893yz();
        }
        if (iK == 4) {
            return new C2850xz(zza);
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
        synchronized (C2893yz.class) {
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
}
