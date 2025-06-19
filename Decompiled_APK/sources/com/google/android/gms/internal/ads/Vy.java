package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Vy extends OA {
    private static final Vy zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private Zy zze;
    private C2893yz zzf;

    static {
        Vy vy = new Vy();
        zza = vy;
        OA.k(Vy.class, vy);
    }

    public static InterfaceC2219jB B() {
        return zza.h();
    }

    public static /* synthetic */ void C(Vy vy, Zy zy) {
        vy.zze = zy;
        vy.zzc |= 1;
    }

    public static /* synthetic */ void D(Vy vy, C2893yz c2893yz) {
        vy.zzf = c2893yz;
        vy.zzc |= 2;
    }

    public static Uy x() {
        return (Uy) zza.g();
    }

    public static Vy y(BA ba, IA ia) {
        return (Vy) OA.o(zza, ba, ia);
    }

    public final C2893yz A() {
        C2893yz c2893yz = this.zzf;
        return c2893yz == null ? C2893yz.y() : c2893yz;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u000b\u0002ဉ\u0000\u0003ဉ\u0001", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new Vy();
        }
        if (iK == 4) {
            return new Uy(zza);
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
        synchronized (Vy.class) {
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

    public final Zy z() {
        Zy zy = this.zze;
        return zy == null ? Zy.y() : zy;
    }
}
