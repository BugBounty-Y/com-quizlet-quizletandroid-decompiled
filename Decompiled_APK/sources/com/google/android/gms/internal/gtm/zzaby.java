package com.google.android.gms.internal.gtm;

import androidx.compose.ui.node.B;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public abstract class zzaby {
    public static zzabq zzb(Class cls) {
        String strI;
        ClassLoader classLoader = zzaby.class.getClassLoader();
        if (cls.equals(zzabq.class)) {
            strI = "com.google.android.gms.internal.gtm.zzyn";
        } else {
            if (!cls.getPackage().equals(zzaby.class.getPackage())) {
                throw new IllegalArgumentException(cls.getName());
            }
            strI = B.i(cls.getPackage().getName(), ".BlazeGenerated", cls.getSimpleName(), "Loader");
        }
        try {
            try {
                try {
                    try {
                        return (zzabq) cls.cast(((zzaby) Class.forName(strI, true, classLoader).getConstructor(null).newInstance(null)).zza());
                    } catch (InvocationTargetException e) {
                        throw new IllegalStateException(e);
                    }
                } catch (NoSuchMethodException e2) {
                    throw new IllegalStateException(e2);
                }
            } catch (IllegalAccessException e3) {
                throw new IllegalStateException(e3);
            } catch (InstantiationException e4) {
                throw new IllegalStateException(e4);
            }
        } catch (ClassNotFoundException unused) {
            Iterator it2 = Collections.singletonList(zzafb.class.getDeclaredConstructor(null).newInstance(null)).iterator();
            ArrayList arrayList = new ArrayList();
            while (it2.hasNext()) {
                try {
                    arrayList.add((zzabq) cls.cast(((zzaby) it2.next()).zza()));
                } catch (ServiceConfigurationError e5) {
                    Logger.getLogger(zzzi.class.getName()).logp(Level.SEVERE, "com.google.protobuf.GeneratedExtensionRegistryLoader", "load", "Unable to load ".concat(cls.getSimpleName()), (Throwable) e5);
                }
            }
            if (arrayList.size() == 1) {
                return (zzabq) arrayList.get(0);
            }
            if (arrayList.size() == 0) {
                return null;
            }
            try {
                return (zzabq) cls.getMethod("combine", Collection.class).invoke(null, arrayList);
            } catch (IllegalAccessException e6) {
                throw new IllegalStateException(e6);
            } catch (NoSuchMethodException e7) {
                throw new IllegalStateException(e7);
            } catch (InvocationTargetException e8) {
                throw new IllegalStateException(e8);
            }
        }
    }

    public abstract zzabq zza();
}
