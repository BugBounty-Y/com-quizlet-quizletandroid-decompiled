package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.RandomAccess;

/* renamed from: com.google.android.gms.internal.ads.us, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2714us extends OA {
    private static final C2714us zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private SA zzd = PA.e;
    private String zze = "";
    private String zzf = "";
    private String zzg = "";

    static {
        C2714us c2714us = new C2714us();
        zza = c2714us;
        OA.k(C2714us.class, c2714us);
    }

    public static C2671ts w() {
        return (C2671ts) zza.g();
    }

    public static /* synthetic */ void x(C2714us c2714us, String str) {
        str.getClass();
        c2714us.zzc |= 1;
        c2714us.zze = str;
    }

    public static void y(C2714us c2714us) {
        RandomAccess randomAccess = c2714us.zzd;
        if (!((AbstractC2690uA) randomAccess).a) {
            PA pa = (PA) randomAccess;
            int i = pa.c;
            c2714us.zzd = pa.d(i + i);
        }
        ((PA) c2714us.zzd).e(2);
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0001\u0000\u0001ࠞ\u0002ဈ\u0000\u0003ဈ\u0001\u0004ဈ\u0002", new Object[]{"zzc", "zzd", U3.u, "zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new C2714us();
        }
        if (iK == 4) {
            return new C2671ts(zza);
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
        synchronized (C2714us.class) {
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
}
