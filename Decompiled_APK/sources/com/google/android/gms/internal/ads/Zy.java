package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Zy extends OA {
    private static final Zy zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private C1988dz zze;
    private BA zzf = BA.b;

    static {
        Zy zy = new Zy();
        zza = zy;
        OA.k(Zy.class, zy);
    }

    public static /* synthetic */ void C(Zy zy, C1988dz c1988dz) {
        zy.zze = c1988dz;
        zy.zzc |= 1;
    }

    public static Yy x() {
        return (Yy) zza.g();
    }

    public static Zy y() {
        return zza;
    }

    public final BA A() {
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
            return new Zy();
        }
        if (iK == 4) {
            return new Yy(zza);
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
        synchronized (Zy.class) {
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

    public final C1988dz z() {
        C1988dz c1988dz = this.zze;
        return c1988dz == null ? C1988dz.y() : c1988dz;
    }
}
