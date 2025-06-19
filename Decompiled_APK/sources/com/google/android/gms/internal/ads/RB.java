package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class RB extends OA {
    private static final RB zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private BA zzd;
    private BA zze;
    private byte zzf = 2;

    static {
        RB rb = new RB();
        zza = rb;
        OA.k(RB.class, rb);
    }

    public RB() {
        C2905zA c2905zA = BA.b;
        this.zzd = c2905zA;
        this.zze = c2905zA;
    }

    public static QB w() {
        return (QB) zza.g();
    }

    public static /* synthetic */ void x(RB rb, C2905zA c2905zA) {
        rb.zzc |= 1;
        rb.zzd = c2905zA;
    }

    public static /* synthetic */ void y(RB rb, C2905zA c2905zA) {
        rb.zzc |= 2;
        rb.zze = c2905zA;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return Byte.valueOf(this.zzf);
            case 1:
                this.zzf = oa == null ? (byte) 0 : (byte) 1;
                return null;
            case 2:
                return new C2391nB(zza, "\u0001\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0001\u0001ᔊ\u0000\u0002ည\u0001", new Object[]{"zzc", "zzd", "zze"});
            case 3:
                return new RB();
            case 4:
                return new QB(zza);
            case 5:
                return zza;
            case 6:
                InterfaceC2219jB interfaceC2219jB = zzb;
                if (interfaceC2219jB != null) {
                    return interfaceC2219jB;
                }
                synchronized (RB.class) {
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
            default:
                throw null;
        }
    }
}
