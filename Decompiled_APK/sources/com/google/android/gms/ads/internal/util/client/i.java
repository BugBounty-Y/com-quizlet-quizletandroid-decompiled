package com.google.android.gms.ads.internal.util.client;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.AbstractC2930zt;
import com.google.android.gms.internal.ads.At;
import com.google.android.gms.internal.ads.C2883yp;
import com.google.android.gms.internal.ads.Is;
import java.lang.reflect.Array;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class i {
    public static final C2883yp a = new C2883yp(new Is(3), 4);

    public static boolean a(Bundle bundle, Bundle bundle2) {
        if (bundle != null && bundle2 != null) {
            if (bundle.size() != bundle2.size()) {
                return false;
            }
            for (String str : bundle.keySet()) {
                if (!bundle2.containsKey(str)) {
                    return false;
                }
                Object obj = bundle.get(str);
                Object obj2 = bundle2.get(str);
                if (obj == null || obj2 == null) {
                    bundle2 = obj2;
                    bundle = obj;
                } else if (obj instanceof Bundle) {
                    if (!(obj2 instanceof Bundle) || !a((Bundle) obj, (Bundle) obj2)) {
                        return false;
                    }
                } else if (obj.getClass().isArray()) {
                    int length = Array.getLength(obj);
                    if (!obj2.getClass().isArray() || length != Array.getLength(obj2)) {
                        return false;
                    }
                    for (int i = 0; i < length; i++) {
                        if (!u.l(Array.get(obj, i), Array.get(obj2, i))) {
                            return false;
                        }
                    }
                } else if (!obj.equals(obj2)) {
                    return false;
                }
            }
            return true;
        }
        return bundle == null && bundle2 == null;
    }

    public static com.google.android.gms.dynamite.c b(Context context) throws zzr {
        try {
            return com.google.android.gms.dynamite.c.c(context, com.google.android.gms.dynamite.c.b, ModuleDescriptor.MODULE_ID);
        } catch (Exception e) {
            throw new zzr(e);
        }
    }

    public static String c(String str) {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        if (stackTrace.length < 4) {
            return str;
        }
        return str + " @" + stackTrace[3].getLineNumber();
    }

    public static void d(String str) {
        if (!k(3) || str.length() <= 4000) {
            return;
        }
        C2883yp c2883yp = a;
        Iterator itE = ((At) c2883yp.b).e(c2883yp, str);
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return;
            }
        }
    }

    public static void e(String str) {
        if (!k(6)) {
            return;
        }
        if (str == null || str.length() <= 4000) {
            Log.e("Ads", str);
            return;
        }
        C2883yp c2883yp = a;
        Iterator itE = ((At) c2883yp.b).e(c2883yp, str);
        boolean z = true;
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return;
            }
            String str2 = (String) abstractC2930zt.next();
            if (z) {
                Log.e("Ads", str2);
            } else {
                Log.e("Ads-cont", str2);
            }
            z = false;
        }
    }

    public static void f(String str, Throwable th) {
        if (k(6)) {
            Log.e("Ads", str, th);
        }
    }

    public static void g(String str) {
        if (!k(4)) {
            return;
        }
        if (str == null || str.length() <= 4000) {
            Log.i("Ads", str);
            return;
        }
        C2883yp c2883yp = a;
        Iterator itE = ((At) c2883yp.b).e(c2883yp, str);
        boolean z = true;
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return;
            }
            String str2 = (String) abstractC2930zt.next();
            if (z) {
                Log.i("Ads", str2);
            } else {
                Log.i("Ads-cont", str2);
            }
            z = false;
        }
    }

    public static void h(String str) {
        if (!k(5)) {
            return;
        }
        if (str == null || str.length() <= 4000) {
            Log.w("Ads", str);
            return;
        }
        C2883yp c2883yp = a;
        Iterator itE = ((At) c2883yp.b).e(c2883yp, str);
        boolean z = true;
        while (true) {
            AbstractC2930zt abstractC2930zt = (AbstractC2930zt) itE;
            if (!abstractC2930zt.hasNext()) {
                return;
            }
            String str2 = (String) abstractC2930zt.next();
            if (z) {
                Log.w("Ads", str2);
            } else {
                Log.w("Ads-cont", str2);
            }
            z = false;
        }
    }

    public static void i(String str, Throwable th) {
        if (k(5)) {
            Log.w("Ads", str, th);
        }
    }

    public static void j(String str, Exception exc) {
        if (k(5)) {
            if (exc != null) {
                i(c(str), exc);
            } else {
                h(c(str));
            }
        }
    }

    public static boolean k(int i) {
        return i >= 5 || Log.isLoggable("Ads", i);
    }
}
