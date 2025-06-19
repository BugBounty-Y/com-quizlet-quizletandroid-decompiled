package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.io.ByteArrayInputStream;

/* loaded from: classes2.dex */
public final class Lz extends OA {
    private static final Lz zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private VA zzd = C2348mB.e;

    static {
        Lz lz = new Lz();
        zza = lz;
        OA.k(Lz.class, lz);
    }

    public static Lz A(ByteArrayInputStream byteArrayInputStream, IA ia) {
        OA oaP = OA.p(zza, new EA(byteArrayInputStream), ia);
        OA.t(oaP);
        return (Lz) oaP;
    }

    public static void C(Lz lz, Kz kz) {
        VA va = lz.zzd;
        if (!((AbstractC2690uA) va).a) {
            int size = va.size();
            lz.zzd = va.d(size + size);
        }
        lz.zzd.add(kz);
    }

    public static Iz y() {
        return (Iz) zza.g();
    }

    public final VA B() {
        return this.zzd;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0002\u0000\u0000\u0001\u0002\u0002\u0000\u0001\u0000\u0001\u000b\u0002\u001b", new Object[]{"zzc", "zzd", Kz.class});
        }
        if (iK == 3) {
            return new Lz();
        }
        if (iK == 4) {
            return new Iz(zza);
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
        synchronized (Lz.class) {
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
        return this.zzd.size();
    }

    public final int x() {
        return this.zzc;
    }

    public final Kz z(int i) {
        return (Kz) this.zzd.get(i);
    }
}
