package com.facebook.appevents.ondeviceprocessing;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import com.facebook.internal.AbstractC1559n;
import com.facebook.o;
import java.util.List;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class e {
    public static final e a = new e();
    public static Boolean b;

    public final Intent a(Context context) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                PackageManager packageManager = context.getPackageManager();
                if (packageManager != null) {
                    Intent intent = new Intent("ReceiverService");
                    intent.setPackage("com.facebook.katana");
                    if (packageManager.resolveService(intent, 0) != null && AbstractC1559n.a(context, "com.facebook.katana")) {
                        return intent;
                    }
                    Intent intent2 = new Intent("ReceiverService");
                    intent2.setPackage("com.facebook.wakizashi");
                    if (packageManager.resolveService(intent2, 0) != null) {
                        if (AbstractC1559n.a(context, "com.facebook.wakizashi")) {
                            return intent2;
                        }
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final int b(c cVar, String str, List list) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return 0;
        }
        try {
            Context contextA = o.a();
            Intent intentA = a(contextA);
            int i = 2;
            if (intentA == null) {
                return 2;
            }
            d dVar = new d();
            try {
                if (!contextA.bindService(intentA, dVar, 1)) {
                    return 3;
                }
                try {
                    dVar.a.await(5L, TimeUnit.SECONDS);
                    IBinder iBinder = dVar.b;
                    if (iBinder != null) {
                        com.facebook.ppml.receiver.c cVarV = com.facebook.ppml.receiver.b.V(iBinder);
                        Bundle bundleA = b.a(cVar, str, list);
                        if (bundleA != null) {
                            ((com.facebook.ppml.receiver.a) cVarV).V(bundleA);
                            bundleA.toString();
                        }
                        i = 1;
                    }
                    contextA.unbindService(dVar);
                    return i;
                } catch (RemoteException unused) {
                    o oVar = o.a;
                    contextA.unbindService(dVar);
                    return 3;
                } catch (InterruptedException unused2) {
                    o oVar2 = o.a;
                    contextA.unbindService(dVar);
                    return 3;
                }
            } catch (Throwable th) {
                contextA.unbindService(dVar);
                o oVar3 = o.a;
                throw th;
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
            return 0;
        }
    }
}
