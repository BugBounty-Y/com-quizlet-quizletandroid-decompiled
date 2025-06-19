package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Kz extends OA {
    private static final Kz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private Ez zzd;
    private int zze;
    private int zzf;
    private int zzg;

    static {
        Kz kz = new Kz();
        zza = kz;
        OA.k(Kz.class, kz);
    }

    public static /* synthetic */ void A(Kz kz, Ez ez) {
        kz.zzd = ez;
        kz.zzc |= 1;
    }

    public static void F(Kz kz, int i) {
        if (i == 1) {
            throw new IllegalArgumentException("Can't get the number of an unknown enum value.");
        }
        kz.zze = i - 2;
    }

    public static Jz y() {
        return (Jz) zza.g();
    }

    public final boolean D() {
        return (this.zzc & 1) != 0;
    }

    public final int E() {
        int i = this.zze;
        int i2 = i != 0 ? i != 1 ? i != 2 ? i != 3 ? 0 : 5 : 4 : 3 : 2;
        if (i2 == 0) {
            return 1;
        }
        return i2;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ဉ\u0000\u0002\f\u0003\u000b\u0004\f", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new Kz();
        }
        if (iK == 4) {
            return new Jz(zza);
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
        synchronized (Kz.class) {
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
        return this.zzf;
    }

    public final Ez x() {
        Ez ez = this.zzd;
        return ez == null ? Ez.y() : ez;
    }

    public final Yz z() {
        Yz yzB = Yz.b(this.zzg);
        return yzB == null ? Yz.UNRECOGNIZED : yzB;
    }
}
