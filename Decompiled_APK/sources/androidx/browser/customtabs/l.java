package androidx.browser.customtabs;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Build;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Log;
import androidx.work.impl.model.n;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes.dex */
public final class l {
    public final android.support.customtabs.d a;
    public final ComponentName b;

    public l(android.support.customtabs.d dVar, ComponentName componentName) {
        this.a = dVar;
        this.b = componentName;
    }

    public static boolean a(Context context, String str, m mVar) {
        mVar.a = context.getApplicationContext();
        Intent intent = new Intent("android.support.customtabs.action.CustomTabsService");
        if (!TextUtils.isEmpty(str)) {
            intent.setPackage(str);
        }
        return context.bindService(intent, mVar, 33);
    }

    public static String b(Context context, List list) {
        PackageManager packageManager = context.getPackageManager();
        List<String> arrayList = list == null ? new ArrayList() : list;
        ResolveInfo resolveInfoResolveActivity = packageManager.resolveActivity(new Intent("android.intent.action.VIEW", Uri.parse("http://")), 0);
        if (resolveInfoResolveActivity != null) {
            String str = resolveInfoResolveActivity.activityInfo.packageName;
            ArrayList arrayList2 = new ArrayList(arrayList.size() + 1);
            arrayList2.add(str);
            if (list != null) {
                arrayList2.addAll(list);
            }
            arrayList = arrayList2;
        }
        Intent intent = new Intent("android.support.customtabs.action.CustomTabsService");
        for (String str2 : arrayList) {
            intent.setPackage(str2);
            if (packageManager.resolveService(intent, 0) != null) {
                return str2;
            }
        }
        if (Build.VERSION.SDK_INT < 30) {
            return null;
        }
        Log.w("CustomTabsClient", "Unable to find any Custom Tabs packages, you may need to add a <queries> element to your manifest. See the docs for CustomTabsClient#getPackageName.");
        return null;
    }

    public final n c(a aVar) {
        g gVar = new g(aVar);
        android.support.customtabs.d dVar = this.a;
        try {
            if (((android.support.customtabs.b) dVar).X(gVar)) {
                return new n(dVar, gVar, this.b);
            }
            return null;
        } catch (RemoteException unused) {
            return null;
        }
    }

    public final void d() {
        try {
            ((android.support.customtabs.b) this.a).p3();
        } catch (RemoteException unused) {
        }
    }
}
