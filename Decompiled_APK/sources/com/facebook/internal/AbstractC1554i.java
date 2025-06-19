package com.facebook.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.net.Uri;
import com.facebook.FacebookSdkNotInitializedException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.internal.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1554i {
    public static final String[] a = {"com.android.chrome", "com.chrome.beta", "com.chrome.dev"};
    public static final /* synthetic */ int b = 0;

    public static EnumC1562q a(int i) {
        for (EnumC1562q enumC1562q : EnumC1562q.values()) {
            if (enumC1562q.a == i) {
                return enumC1562q;
            }
        }
        return EnumC1562q.Unknown;
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x01d7  */
    /* JADX WARN: Removed duplicated region for block: B:118:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:26:0x007b  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0121  */
    /* JADX WARN: Removed duplicated region for block: B:5:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x013e A[Catch: all -> 0x00eb, Exception -> 0x00ef, TryCatch #9 {Exception -> 0x00ef, all -> 0x00eb, blocks: (B:40:0x00c7, B:42:0x00d5, B:44:0x00d9, B:52:0x00f2, B:54:0x010c, B:56:0x0119, B:63:0x0138, B:65:0x013e, B:68:0x014a, B:70:0x014e, B:71:0x0158, B:59:0x0123, B:61:0x0130, B:94:0x01bd, B:95:0x01c4), top: B:116:0x00c7 }] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x014a A[Catch: all -> 0x00eb, Exception -> 0x00ef, TryCatch #9 {Exception -> 0x00ef, all -> 0x00eb, blocks: (B:40:0x00c7, B:42:0x00d5, B:44:0x00d9, B:52:0x00f2, B:54:0x010c, B:56:0x0119, B:63:0x0138, B:65:0x013e, B:68:0x014a, B:70:0x014e, B:71:0x0158, B:59:0x0123, B:61:0x0130, B:94:0x01bd, B:95:0x01c4), top: B:116:0x00c7 }] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x014e A[Catch: all -> 0x00eb, Exception -> 0x00ef, TryCatch #9 {Exception -> 0x00ef, all -> 0x00eb, blocks: (B:40:0x00c7, B:42:0x00d5, B:44:0x00d9, B:52:0x00f2, B:54:0x010c, B:56:0x0119, B:63:0x0138, B:65:0x013e, B:68:0x014a, B:70:0x014e, B:71:0x0158, B:59:0x0123, B:61:0x0130, B:94:0x01bd, B:95:0x01c4), top: B:116:0x00c7 }] */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0158 A[Catch: all -> 0x00eb, Exception -> 0x00ef, TRY_LEAVE, TryCatch #9 {Exception -> 0x00ef, all -> 0x00eb, blocks: (B:40:0x00c7, B:42:0x00d5, B:44:0x00d9, B:52:0x00f2, B:54:0x010c, B:56:0x0119, B:63:0x0138, B:65:0x013e, B:68:0x014a, B:70:0x014e, B:71:0x0158, B:59:0x0123, B:61:0x0130, B:94:0x01bd, B:95:0x01c4), top: B:116:0x00c7 }] */
    /* JADX WARN: Removed duplicated region for block: B:92:0x01b9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.facebook.internal.C1548c b(android.content.Context r15) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 475
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.AbstractC1554i.b(android.content.Context):com.facebook.internal.c");
    }

    public static final String c() {
        if (!com.facebook.internal.instrument.crashshield.a.b(AbstractC1554i.class)) {
            try {
                Context contextA = com.facebook.o.a();
                List<ResolveInfo> listQueryIntentServices = contextA.getPackageManager().queryIntentServices(new Intent("android.support.customtabs.action.CustomTabsService"), 0);
                Intrinsics.checkNotNullExpressionValue(listQueryIntentServices, "context.packageManager.q…ervices(serviceIntent, 0)");
                String[] strArr = a;
                Intrinsics.checkNotNullParameter(strArr, "<this>");
                HashSet hashSet = new HashSet(U.a(3));
                C4933y.L(strArr, hashSet);
                Iterator<ResolveInfo> it2 = listQueryIntentServices.iterator();
                while (it2.hasNext()) {
                    ServiceInfo serviceInfo = it2.next().serviceInfo;
                    if (serviceInfo != null && hashSet.contains(serviceInfo.packageName)) {
                        return serviceInfo.packageName;
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(AbstractC1554i.class, th);
                return null;
            }
        }
        return null;
    }

    public static final String d() {
        if (com.facebook.internal.instrument.crashshield.a.b(AbstractC1554i.class)) {
            return null;
        }
        try {
            return "fbconnect://cct." + com.facebook.o.a().getPackageName();
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(AbstractC1554i.class, th);
            return null;
        }
    }

    public static final String e(String developerDefinedRedirectURI) {
        if (com.facebook.internal.instrument.crashshield.a.b(AbstractC1554i.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(developerDefinedRedirectURI, "developerDefinedRedirectURI");
            return f(com.facebook.o.a(), developerDefinedRedirectURI) ? developerDefinedRedirectURI : f(com.facebook.o.a(), d()) ? d() : "";
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(AbstractC1554i.class, th);
            return null;
        }
    }

    public static final boolean f(Context context, String redirectURI) {
        List<ResolveInfo> listQueryIntentActivities;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(redirectURI, "redirectURI");
        PackageManager packageManager = context.getPackageManager();
        if (packageManager != null) {
            Intent intent = new Intent();
            intent.setAction("android.intent.action.VIEW");
            intent.addCategory("android.intent.category.DEFAULT");
            intent.addCategory("android.intent.category.BROWSABLE");
            intent.setData(Uri.parse(redirectURI));
            listQueryIntentActivities = packageManager.queryIntentActivities(intent, 64);
        } else {
            listQueryIntentActivities = null;
        }
        if (listQueryIntentActivities != null) {
            Iterator<ResolveInfo> it2 = listQueryIntentActivities.iterator();
            boolean z = false;
            while (it2.hasNext()) {
                ActivityInfo activityInfo = it2.next().activityInfo;
                if (Intrinsics.b(activityInfo.name, "com.facebook.CustomTabActivity") && Intrinsics.b(activityInfo.packageName, context.getPackageName())) {
                    z = true;
                }
            }
            return z;
        }
        return false;
    }

    public static boolean g(Context context) throws ClassNotFoundException {
        Method methodV = J.v("com.google.android.gms.common.GooglePlayServicesUtil", "isGooglePlayServicesAvailable", Context.class);
        if (methodV != null) {
            Object objY = J.y(null, methodV, context);
            if ((objY instanceof Integer) && Intrinsics.b(objY, 0)) {
                return true;
            }
        }
        return false;
    }

    public static final void h(String arg, String name) {
        Intrinsics.checkNotNullParameter(arg, "arg");
        Intrinsics.checkNotNullParameter(name, "name");
        if (arg.length() <= 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Argument '", name, "' cannot be empty").toString());
        }
    }

    public static final void i(com.facebook.v container) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter("requests", "name");
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter("requests", "name");
        Iterator it2 = container.iterator();
        while (it2.hasNext()) {
            if (it2.next() == null) {
                throw new NullPointerException("Container 'requests' cannot contain null values");
            }
        }
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter("requests", "name");
        if (container.isEmpty()) {
            throw new IllegalArgumentException("Container 'requests' cannot be empty".toString());
        }
    }

    public static final void j(String str, String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        if (str == null || str.length() <= 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.B("Argument '", name, "' cannot be null or empty").toString());
        }
    }

    public static final void k() {
        if (!com.facebook.o.o.get()) {
            throw new FacebookSdkNotInitializedException("The SDK has not been initialized, make sure to call FacebookSdk.sdkInitialize() first.");
        }
    }
}
