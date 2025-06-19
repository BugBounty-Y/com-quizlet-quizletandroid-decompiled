package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.RemoteException;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2086g8;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.S7;

/* renamed from: com.google.android.gms.ads.internal.client.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1612p {
    public static final S a;

    static {
        S q = null;
        try {
            Object objNewInstance = C1608n.class.getClassLoader().loadClass("com.google.android.gms.ads.internal.ClientApi").getDeclaredConstructor(null).newInstance(null);
            if (objNewInstance instanceof IBinder) {
                IBinder iBinder = (IBinder) objNewInstance;
                if (iBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IClientApi");
                    q = iInterfaceQueryLocalInterface instanceof S ? (S) iInterfaceQueryLocalInterface : new Q(iBinder, "com.google.android.gms.ads.internal.client.IClientApi", 0);
                }
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("ClientApi class is not an instance of IBinder.");
            }
        } catch (Exception unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Failed to instantiate ClientApi class.");
        }
        a = q;
    }

    public abstract Object a();

    public abstract Object b(S s);

    public abstract Object c();

    public final Object d(Context context, boolean z) {
        boolean z2;
        Object objC;
        Object objB;
        if (!z) {
            com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
            if (com.google.android.gms.common.c.b.c(context, 12451000) != 0) {
                com.google.android.gms.ads.internal.util.client.i.d("Google Play Services is not available.");
                z = true;
            }
        }
        boolean z3 = false;
        boolean z4 = !(com.google.android.gms.dynamite.c.a(context, ModuleDescriptor.MODULE_ID) <= com.google.android.gms.dynamite.c.d(context, ModuleDescriptor.MODULE_ID, false));
        AbstractC2773w7.a(context);
        if (((Boolean) S7.a.o()).booleanValue()) {
            z2 = false;
        } else if (((Boolean) S7.b.o()).booleanValue()) {
            z2 = true;
            z3 = true;
        } else {
            z3 = z | z4;
            z2 = false;
        }
        S s = a;
        Object objB2 = null;
        if (z3) {
            if (s != null) {
                try {
                    objB = b(s);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke local loader using ClientApi class.", e);
                }
                if (objB == null && !z2) {
                    try {
                        objB2 = c();
                    } catch (RemoteException e2) {
                        com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke remote loader.", e2);
                    }
                    objB = objB2;
                }
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("ClientApi class cannot be loaded.");
            }
            objB = null;
            if (objB == null) {
                objB2 = c();
                objB = objB2;
            }
        } else {
            try {
                objC = c();
            } catch (RemoteException e3) {
                com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke remote loader.", e3);
                objC = null;
            }
            if (objC == null) {
                int iIntValue = ((Long) AbstractC2086g8.a.o()).intValue();
                C1614q c1614q = C1614q.f;
                if (c1614q.e.nextInt(iIntValue) == 0) {
                    Bundle bundle = new Bundle();
                    bundle.putString("action", "dynamite_load");
                    bundle.putInt("is_missing", 1);
                    String str = c1614q.d.a;
                    com.google.android.gms.ads.internal.util.client.c cVar2 = c1614q.a;
                    cVar2.getClass();
                    com.google.android.gms.ads.internal.util.client.c.m(context, str, bundle, new com.google.android.gms.internal.mlkit_common.u(cVar2));
                }
            }
            if (objC == null) {
                if (s != null) {
                    try {
                        objB2 = b(s);
                    } catch (RemoteException e4) {
                        com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke local loader using ClientApi class.", e4);
                    }
                } else {
                    com.google.android.gms.ads.internal.util.client.i.h("ClientApi class cannot be loaded.");
                }
                objB = objB2;
            } else {
                objB = objC;
            }
        }
        return objB == null ? a() : objB;
    }
}
