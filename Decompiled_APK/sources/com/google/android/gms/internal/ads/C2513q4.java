package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.q4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2513q4 extends OA {
    private static final C2513q4 zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private BA zzd;
    private BA zze;
    private BA zzf;
    private BA zzg;

    static {
        C2513q4 c2513q4 = new C2513q4();
        zza = c2513q4;
        OA.k(C2513q4.class, c2513q4);
    }

    public C2513q4() {
        C2905zA c2905zA = BA.b;
        this.zzd = c2905zA;
        this.zze = c2905zA;
        this.zzf = c2905zA;
        this.zzg = c2905zA;
    }

    public static /* synthetic */ void C(C2513q4 c2513q4, C2905zA c2905zA) {
        c2513q4.zzc |= 1;
        c2513q4.zzd = c2905zA;
    }

    public static /* synthetic */ void D(C2513q4 c2513q4, C2905zA c2905zA) {
        c2513q4.zzc |= 2;
        c2513q4.zze = c2905zA;
    }

    public static /* synthetic */ void E(C2513q4 c2513q4, C2905zA c2905zA) {
        c2513q4.zzc |= 8;
        c2513q4.zzg = c2905zA;
    }

    public static /* synthetic */ void F(C2513q4 c2513q4, C2905zA c2905zA) {
        c2513q4.zzc |= 4;
        c2513q4.zzf = c2905zA;
    }

    public static C2470p4 w() {
        return (C2470p4) zza.g();
    }

    public static C2513q4 x(byte[] bArr, IA ia) throws zzgzh {
        OA oaU = OA.u(zza, bArr, bArr.length, ia);
        OA.t(oaU);
        return (C2513q4) oaU;
    }

    public final BA A() {
        return this.zzg;
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
            return new C2391nB(zza, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001ည\u0000\u0002ည\u0001\u0003ည\u0002\u0004ည\u0003", new Object[]{"zzc", "zzd", "zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new C2513q4();
        }
        if (iK == 4) {
            return new C2470p4(zza);
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
        synchronized (C2513q4.class) {
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

    public final BA y() {
        return this.zzd;
    }

    public final BA z() {
        return this.zze;
    }
}
