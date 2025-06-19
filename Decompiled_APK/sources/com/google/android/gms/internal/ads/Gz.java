package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Gz extends OA {
    private static final Gz zza;
    private static volatile InterfaceC2219jB zzb;
    private String zzc = "";
    private BA zzd = BA.b;
    private int zze;

    static {
        Gz gz = new Gz();
        zza = gz;
        OA.k(Gz.class, gz);
    }

    public static /* synthetic */ void D(Gz gz, String str) {
        str.getClass();
        gz.zzc = str;
    }

    public static /* synthetic */ void E(Gz gz, BA ba) {
        ba.getClass();
        gz.zzd = ba;
    }

    public static Fz w() {
        return (Fz) zza.g();
    }

    public static Gz x() {
        return zza;
    }

    public static Gz y(byte[] bArr, IA ia) {
        OA oaU = OA.u(zza, bArr, bArr.length, ia);
        OA.t(oaU);
        return (Gz) oaU;
    }

    public final BA A() {
        return this.zzd;
    }

    public final String B() {
        return this.zzc;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0000\u0001\u0003\u0003\u0000\u0000\u0000\u0001Ȉ\u0002\n\u0003\f", new Object[]{"zzc", "zzd", "zze"});
        }
        if (iK == 3) {
            return new Gz();
        }
        if (iK == 4) {
            return new Fz(zza);
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
        synchronized (Gz.class) {
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

    public final Yz z() {
        Yz yzB = Yz.b(this.zze);
        return yzB == null ? Yz.UNRECOGNIZED : yzB;
    }
}
