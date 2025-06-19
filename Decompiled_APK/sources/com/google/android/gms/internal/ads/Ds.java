package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;

/* loaded from: classes2.dex */
public final class Ds {
    public final Fs a;
    public final boolean b = true;

    public Ds(Fs fs) {
        this.a = fs;
    }

    public static Ds a(Context context, String str) throws zzfoz {
        Fs es;
        try {
            try {
                try {
                    IBinder iBinderB = com.google.android.gms.dynamite.c.c(context, com.google.android.gms.dynamite.c.b, ModuleDescriptor.MODULE_ID).b("com.google.android.gms.gass.internal.clearcut.GassDynamiteClearcutLogger");
                    if (iBinderB == null) {
                        es = null;
                    } else {
                        IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.gass.internal.clearcut.IGassClearcut");
                        es = iInterfaceQueryLocalInterface instanceof Fs ? (Fs) iInterfaceQueryLocalInterface : new Es(iBinderB, "com.google.android.gms.gass.internal.clearcut.IGassClearcut", 0);
                    }
                    es.y3(new com.google.android.gms.dynamic.b(context), str);
                    Log.i("GASS", "GassClearcutLogger Initialized.");
                    return new Ds(es);
                } catch (RemoteException | zzfoz | NullPointerException | SecurityException unused) {
                    return new Ds(new Gs());
                }
            } catch (Exception e) {
                throw new zzfoz(e);
            }
        } catch (Exception e2) {
            throw new zzfoz(e2);
        }
    }
}
