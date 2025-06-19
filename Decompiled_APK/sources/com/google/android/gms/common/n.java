package com.google.android.gms.common;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.internal.r;
import com.google.android.gms.common.internal.s;
import com.google.android.gms.common.internal.t;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.dynamite.DynamiteModule$LoadingException;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3501n3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3507o3;

/* loaded from: classes2.dex */
public abstract class n {
    public static final j a;
    public static final j b;
    public static volatile t c;
    public static final Object d;
    public static Context e;

    static {
        new j(0, k.I3("0\u0082\u0005È0\u0082\u0003° \u0003\u0002\u0001\u0002\u0002\u0014\u007f¢fú§p\u0085xb±"));
        new j(1, k.I3("0\u0082\u0006\u00040\u0082\u0003ì \u0003\u0002\u0001\u0002\u0002\u0014QÕÛ\u0004÷XçB\u0086<"));
        new j(2, k.I3("0\u0082\u0005È0\u0082\u0003° \u0003\u0002\u0001\u0002\u0002\u0014\u0010\u008ae\bsù/\u008eQí"));
        new j(3, k.I3("0\u0082\u0006\u00040\u0082\u0003ì \u0003\u0002\u0001\u0002\u0002\u0014\u0003£²\u00ad×árÊkì"));
        a = new j(4, k.I3("0\u0082\u0004C0\u0082\u0003+ \u0003\u0002\u0001\u0002\u0002\t\u0000Âà\u0087FdJ0\u008d0"));
        b = new j(5, k.I3("0\u0082\u0004¨0\u0082\u0003\u0090 \u0003\u0002\u0001\u0002\u0002\t\u0000Õ\u0085¸l}ÓNõ0"));
        d = new Object();
    }

    public static void a() {
        t rVar;
        if (c != null) {
            return;
        }
        u.h(e);
        synchronized (d) {
            try {
                if (c == null) {
                    IBinder iBinderB = com.google.android.gms.dynamite.c.c(e, com.google.android.gms.dynamite.c.e, "com.google.android.gms.googlecertificates").b("com.google.android.gms.common.GoogleCertificatesImpl");
                    int i = s.b;
                    if (iBinderB == null) {
                        rVar = null;
                    } else {
                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.common.internal.IGoogleCertificatesApi");
                        rVar = iInterfaceQueryLocalInterface instanceof t ? (t) iInterfaceQueryLocalInterface : new r(iBinderB, "com.google.android.gms.common.internal.IGoogleCertificatesApi", 3);
                    }
                    c = rVar;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static h b(zzt zztVar) {
        boolean z = zztVar.a;
        int i = zztVar.d;
        if (z) {
            zzt zztVar2 = zztVar.f;
            if (zztVar2 != null) {
                b(zztVar2);
            }
            AbstractC3507o3.d(i);
            return new h(true, null, null);
        }
        int i2 = zztVar.c;
        PackageManager.NameNotFoundException nameNotFoundException = AbstractC3501n3.c(i2) == 4 ? new PackageManager.NameNotFoundException() : null;
        String str = zztVar.b;
        if (str == null) {
            str = "error checking package certificate";
        }
        AbstractC3507o3.d(i);
        AbstractC3501n3.c(i2);
        return new h(false, str, nameNotFoundException);
    }

    public static h c(String str, l lVar, boolean z, boolean z2) {
        try {
            a();
            u.h(e);
            zzv zzvVar = new zzv(str, lVar, z, z2);
            try {
                t tVar = c;
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(e.getPackageManager());
                r rVar = (r) tVar;
                Parcel parcelF3 = rVar.f3();
                int i = com.google.android.gms.internal.common.h.a;
                boolean z3 = true;
                parcelF3.writeInt(1);
                zzvVar.writeToParcel(parcelF3, 0);
                com.google.android.gms.internal.common.h.b(parcelF3, bVar);
                Parcel parcelL2 = rVar.L2(5, parcelF3);
                if (parcelL2.readInt() == 0) {
                    z3 = false;
                }
                parcelL2.recycle();
                return z3 ? h.c : new p(new o(z, str, lVar));
            } catch (RemoteException e2) {
                Log.e("GoogleCertificates", "Failed to get Google certificates from remote", e2);
                return h.c("module call", e2);
            }
        } catch (DynamiteModule$LoadingException e3) {
            Log.e("GoogleCertificates", "Failed to get Google certificates from remote", e3);
            return h.c("module init: ".concat(String.valueOf(e3.getMessage())), e3);
        }
    }
}
