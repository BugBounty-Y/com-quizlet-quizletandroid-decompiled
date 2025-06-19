package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes2.dex */
public final class Py extends OA {
    private static final Py zza;
    private static volatile InterfaceC2219jB zzb;
    private int zzc;
    private int zzd;
    private BA zze = BA.b;
    private Ty zzf;

    static {
        Py py = new Py();
        zza = py;
        OA.k(Py.class, py);
    }

    public static InterfaceC2219jB B() {
        return zza.h();
    }

    public static /* synthetic */ void D(Py py, Ty ty) {
        py.zzf = ty;
        py.zzc |= 1;
    }

    public static Oy x() {
        return (Oy) zza.g();
    }

    public static Py y(BA ba, IA ia) {
        return (Py) OA.o(zza, ba, ia);
    }

    public final BA A() {
        return this.zze;
    }

    @Override // com.google.android.gms.internal.ads.OA
    public final Object s(int i, OA oa) {
        InterfaceC2219jB na;
        int iK = AbstractC0147y.k(i);
        if (iK == 0) {
            return (byte) 1;
        }
        if (iK == 2) {
            return new C2391nB(zza, "\u0000\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001\u000b\u0002\n\u0003ဉ\u0000", new Object[]{"zzc", "zzd", "zze", "zzf"});
        }
        if (iK == 3) {
            return new Py();
        }
        if (iK == 4) {
            return new Oy(zza);
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
        synchronized (Py.class) {
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
        return this.zzd;
    }

    public final Ty z() {
        Ty ty = this.zzf;
        return ty == null ? Ty.y() : ty;
    }
}
