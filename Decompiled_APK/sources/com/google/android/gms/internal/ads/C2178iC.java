package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.iC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2178iC extends OA {
    private static final C2178iC zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private UB zzf;
    private WB zzg;
    private int zzh;
    private int zzk;
    private byte zzm = 2;
    private String zze = "";
    private SA zzi = PA.e;
    private String zzj = "";
    private VA zzl = C2348mB.e;

    static {
        C2178iC c2178iC = new C2178iC();
        zza = c2178iC;
        OA.k(C2178iC.class, c2178iC);
    }

    public static /* synthetic */ void A(C2178iC c2178iC, int i) {
        c2178iC.zzc |= 1;
        c2178iC.zzd = i;
    }

    public static /* synthetic */ void B(C2178iC c2178iC, UB ub) {
        c2178iC.zzf = ub;
        c2178iC.zzc |= 4;
    }

    public static /* synthetic */ void C(C2178iC c2178iC, String str) {
        str.getClass();
        c2178iC.zzc |= 2;
        c2178iC.zze = str;
    }

    public static /* synthetic */ void D(C2178iC c2178iC, int i) {
        c2178iC.zzk = i - 1;
        c2178iC.zzc |= 64;
    }

    public static C2134hC x() {
        return (C2134hC) zza.g();
    }

    public static void z(C2178iC c2178iC, String str) {
        str.getClass();
        VA va = c2178iC.zzl;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            c2178iC.zzl = va.d(size + size);
        }
        c2178iC.zzl.add(str);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return Byte.valueOf(this.zzm);
            case 1:
                this.zzm = oa == null ? (byte) 0 : (byte) 1;
                return null;
            case 2:
                return new C2391nB(zza, "\u0001\t\u0000\u0001\u0001\t\t\u0000\u0002\u0003\u0001ᔄ\u0000\u0002ဈ\u0001\u0003ᐉ\u0002\u0004ᐉ\u0003\u0005င\u0004\u0006\u0016\u0007ဈ\u0005\b᠌\u0006\t\u001a", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg", "zzh", "zzi", "zzj", "zzk", C1828aC.f, "zzl"});
            case 3:
                return new C2178iC();
            case 4:
                return new C2134hC(zza);
            case 5:
                return zza;
            case 6:
                InterfaceC2219jB interfaceC2219jB = zzb;
                if (interfaceC2219jB != null) {
                    return interfaceC2219jB;
                }
                synchronized (C2178iC.class) {
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

    public final int w() {
        return this.zzl.size();
    }

    public final String y() {
        return this.zze;
    }
}
