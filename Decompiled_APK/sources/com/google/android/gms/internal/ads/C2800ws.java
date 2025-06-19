package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.ws, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2800ws extends OA {
    private static final C2800ws zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private String zze = "";
    private String zzf = "";
    private C2714us zzg;

    static {
        C2800ws c2800ws = new C2800ws();
        zza = c2800ws;
        OA.k(C2800ws.class, c2800ws);
    }

    public static C2757vs w() {
        return (C2757vs) zza.g();
    }

    public static /* synthetic */ void x(C2800ws c2800ws, String str) {
        str.getClass();
        c2800ws.zzc |= 2;
        c2800ws.zze = str;
    }

    public static /* synthetic */ void y(C2800ws c2800ws, C2714us c2714us) {
        c2800ws.zzg = c2714us;
        c2800ws.zzc |= 8;
    }

    public static /* synthetic */ void z(C2800ws c2800ws) {
        c2800ws.zzd = 1;
        c2800ws.zzc = 1 | c2800ws.zzc;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0000\u0000\u0001᠌\u0000\u0002ဈ\u0001\u0003ဈ\u0002\u0004ဉ\u0003", new Object[]{"zzc", "zzd", U3.v, "zze", "zzf", "zzg"});
        }
        if (iK == 3) {
            return new C2800ws();
        }
        if (iK == 4) {
            return new C2757vs(zza);
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
        synchronized (C2800ws.class) {
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
