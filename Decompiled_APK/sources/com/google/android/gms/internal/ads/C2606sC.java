package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: com.google.android.gms.internal.ads.sC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2606sC extends OA {
    private static final C2606sC zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private String zzd = "";
    private String zze = "";
    private int zzf = 4;
    private VA zzg;
    private String zzh;
    private String zzi;
    private boolean zzj;
    private double zzk;
    private VA zzl;
    private int zzm;
    private boolean zzn;
    private boolean zzo;
    private boolean zzp;
    private boolean zzu;

    static {
        C2606sC c2606sC = new C2606sC();
        zza = c2606sC;
        OA.k(C2606sC.class, c2606sC);
    }

    public C2606sC() {
        C2348mB c2348mB = C2348mB.e;
        this.zzg = c2348mB;
        this.zzh = "";
        this.zzi = "";
        this.zzl = c2348mB;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0001\u000e\u0000\u0001\u0001\u000e\u000e\u0000\u0002\u0000\u0001ဈ\u0000\u0002᠌\u0002\u0003\u001a\u0004ဈ\u0003\u0005ဈ\u0004\u0006ဇ\u0005\u0007က\u0006\b\u001b\tဈ\u0001\n᠌\u0007\u000bဇ\b\fဇ\t\rဇ\n\u000eဇ\u000b", new Object[]{"zzc", "zzd", "zzf", C1828aC.k, "zzg", "zzh", "zzi", "zzj", "zzk", "zzl", C2521qC.class, "zze", "zzm", C1828aC.j, "zzn", "zzo", "zzp", "zzu"});
        }
        if (iK == 3) {
            return new C2606sC();
        }
        if (iK == 4) {
            return new XB(zza);
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
        synchronized (C2606sC.class) {
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
