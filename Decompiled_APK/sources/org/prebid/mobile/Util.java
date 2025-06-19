package org.prebid.mobile;

import android.os.Bundle;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Random;

/* loaded from: classes3.dex */
public abstract class Util {
    public static final HashSet a;

    static {
        new Random();
        a = new HashSet();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static void a(HashMap map, AdManagerAdRequest adManagerAdRequest) {
        Bundle bundle;
        if (adManagerAdRequest == 0) {
            return;
        }
        if (AdManagerAdRequest.class == c("com.google.android.gms.ads.doubleclick.PublisherAdRequest") || AdManagerAdRequest.class == c("com.google.android.gms.ads.admanager.AdManagerAdRequest")) {
            d(adManagerAdRequest);
            if (map == null || map.isEmpty() || (bundle = (Bundle) b(adManagerAdRequest, "getCustomTargeting", new Object[0])) == null) {
                return;
            }
            for (String str : map.keySet()) {
                bundle.putString(str, (String) map.get(str));
                HashSet hashSet = a;
                synchronized (hashSet) {
                    hashSet.add(str);
                }
            }
            return;
        }
        if (AdManagerAdRequest.class == c("com.google.android.gms.ads.doubleclick.PublisherAdRequest$Builder") || AdManagerAdRequest.class == c("com.google.android.gms.ads.admanager.AdManagerAdRequest$Builder")) {
            d(b(adManagerAdRequest, "build", new Object[0]));
            if (map == null || map.isEmpty()) {
                return;
            }
            for (String str2 : map.keySet()) {
                b(adManagerAdRequest, "addCustomTargeting", str2, map.get(str2));
                HashSet hashSet2 = a;
                synchronized (hashSet2) {
                    hashSet2.add(str2);
                }
            }
            return;
        }
        if (AdManagerAdRequest.class == c("android.os.Bundle")) {
            Bundle bundle2 = (Bundle) adManagerAdRequest;
            if (map != null) {
                for (Map.Entry entry : map.entrySet()) {
                    bundle2.putString((String) entry.getKey(), (String) entry.getValue());
                }
                return;
            }
            return;
        }
        if (AdManagerAdRequest.class == c("com.applovin.mediation.nativeAds.MaxNativeAdLoader")) {
            try {
                AdManagerAdRequest.class.getMethod("setLocalExtraParameter", String.class, Object.class).invoke(adManagerAdRequest, "PrebidMaxMediationAdapterExtraKeywordsId", map);
            } catch (Exception unused) {
                LogUtil.b("Util", "Can't call method: setLocalExtraParameter() on object " + AdManagerAdRequest.class);
            }
        }
    }

    public static Object b(Object obj, String str, Object... objArr) {
        try {
            int length = objArr.length;
            Class<?>[] clsArr = new Class[length];
            for (int i = 0; i < length; i++) {
                clsArr[i] = objArr[i].getClass();
            }
            return obj.getClass().getMethod(str, clsArr).invoke(obj, objArr);
        } catch (Exception unused) {
            StringBuilder sbY = android.support.v4.media.session.a.y("Can't call method: ", str, "() on object ");
            sbY.append(obj.getClass());
            LogUtil.b("Util", sbY.toString());
            return null;
        }
    }

    public static Class c(String str) {
        try {
            return Class.forName(str);
        } catch (ClassNotFoundException unused) {
            return null;
        }
    }

    public static void d(Object obj) {
        HashSet hashSet;
        Bundle bundle = (Bundle) b(obj, "getCustomTargeting", new Object[0]);
        if (bundle == null || (hashSet = a) == null) {
            return;
        }
        Iterator it2 = hashSet.iterator();
        while (it2.hasNext()) {
            bundle.remove((String) it2.next());
        }
    }
}
