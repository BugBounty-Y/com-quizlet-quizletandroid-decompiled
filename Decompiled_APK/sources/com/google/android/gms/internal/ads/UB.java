package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class UB extends OA {
    private static final UB zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private TB zzd;
    private BA zzf;
    private BA zzg;
    private int zzh;
    private byte zzi = 2;
    private VA zze = C2348mB.e;

    static {
        UB ub = new UB();
        zza = ub;
        OA.k(UB.class, ub);
    }

    public UB() {
        C2905zA c2905zA = BA.b;
        this.zzf = c2905zA;
        this.zzg = c2905zA;
    }

    public static SB w() {
        return (SB) zza.g();
    }

    public static void x(UB ub, RB rb) {
        VA va = ub.zze;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            ub.zze = va.d(size + size);
        }
        ub.zze.add(rb);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return Byte.valueOf(this.zzi);
            case 1:
                this.zzi = oa == null ? (byte) 0 : (byte) 1;
                return null;
            case 2:
                return new C2391nB(zza, "\u0001\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0001\u0001\u0001ဉ\u0000\u0002Л\u0003ည\u0001\u0004ည\u0002\u0005င\u0003", new Object[]{"zzc", "zzd", "zze", RB.class, "zzf", "zzg", "zzh"});
            case 3:
                return new UB();
            case 4:
                return new SB(zza);
            case 5:
                return zza;
            case 6:
                InterfaceC2219jB interfaceC2219jB = zzb;
                if (interfaceC2219jB != null) {
                    return interfaceC2219jB;
                }
                synchronized (UB.class) {
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
