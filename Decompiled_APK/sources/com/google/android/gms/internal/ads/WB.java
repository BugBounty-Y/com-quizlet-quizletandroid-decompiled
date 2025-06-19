package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class WB extends OA {
    private static final WB zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private VB zzd;
    private BA zzf;
    private BA zzg;
    private int zzh;
    private BA zzi;
    private byte zzj = 2;
    private VA zze = C2348mB.e;

    static {
        WB wb = new WB();
        zza = wb;
        OA.k(WB.class, wb);
    }

    public WB() {
        C2905zA c2905zA = BA.b;
        this.zzf = c2905zA;
        this.zzg = c2905zA;
        this.zzi = c2905zA;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return Byte.valueOf(this.zzj);
            case 1:
                this.zzj = oa == null ? (byte) 0 : (byte) 1;
                return null;
            case 2:
                return new C2391nB(zza, "\u0001\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0001\u0001\u0001ဉ\u0000\u0002Л\u0003ည\u0001\u0004ည\u0002\u0005င\u0003\u0006ည\u0004", new Object[]{"zzc", "zzd", "zze", RB.class, "zzf", "zzg", "zzh", "zzi"});
            case 3:
                return new WB();
            case 4:
                return new C1954d7(zza);
            case 5:
                return zza;
            case 6:
                InterfaceC2219jB interfaceC2219jB = zzb;
                if (interfaceC2219jB != null) {
                    return interfaceC2219jB;
                }
                synchronized (WB.class) {
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
