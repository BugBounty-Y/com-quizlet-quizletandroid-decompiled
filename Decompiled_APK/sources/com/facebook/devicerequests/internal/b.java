package com.facebook.devicerequests.internal;

import android.net.nsd.NsdManager;
import android.net.nsd.NsdServiceInfo;
import com.facebook.internal.F;
import com.facebook.internal.v;
import com.facebook.internal.y;
import com.facebook.o;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes.dex */
public final class b {
    public static final b a = new b();
    public static final HashMap b = new HashMap();

    public static final void a(String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return;
        }
        try {
            b bVar = a;
            if (com.facebook.internal.instrument.crashshield.a.b(bVar)) {
                return;
            }
            HashMap map = b;
            try {
                NsdManager.RegistrationListener registrationListener = (NsdManager.RegistrationListener) map.get(str);
                if (registrationListener != null) {
                    Object systemService = o.a().getSystemService("servicediscovery");
                    Intrinsics.e(systemService, "null cannot be cast to non-null type android.net.nsd.NsdManager");
                    try {
                        ((NsdManager) systemService).unregisterService(registrationListener);
                    } catch (IllegalArgumentException unused) {
                        o oVar = o.a;
                    }
                    map.remove(str);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(bVar, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th2);
        }
    }

    public static final boolean b() {
        if (com.facebook.internal.instrument.crashshield.a.b(b.class)) {
            return false;
        }
        try {
            v vVarB = y.b(o.b());
            if (vVarB != null) {
                if (vVarB.c.contains(F.c)) {
                    return true;
                }
            }
            return false;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(b.class, th);
            return false;
        }
    }

    public final boolean c(String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return false;
        }
        try {
            HashMap map = b;
            if (map.containsKey(str)) {
                return true;
            }
            o oVar = o.a;
            String str2 = "fbsdk_" + ("android-" + D.p("18.0.3", '.', '|')) + '_' + str;
            NsdServiceInfo nsdServiceInfo = new NsdServiceInfo();
            nsdServiceInfo.setServiceType("_fb._tcp.");
            nsdServiceInfo.setServiceName(str2);
            nsdServiceInfo.setPort(80);
            Object systemService = o.a().getSystemService("servicediscovery");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.net.nsd.NsdManager");
            a aVar = new a(str2, str);
            map.put(str, aVar);
            ((NsdManager) systemService).registerService(nsdServiceInfo, 1, aVar);
            return true;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return false;
        }
    }
}
