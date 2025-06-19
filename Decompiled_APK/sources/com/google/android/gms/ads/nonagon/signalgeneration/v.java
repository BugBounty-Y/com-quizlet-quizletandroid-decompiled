package com.google.android.gms.ads.nonagon.signalgeneration;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.util.Base64;
import android.webkit.WebView;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.ads.AbstractC1911c8;
import com.google.android.gms.internal.ads.AbstractC2459ou;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.Nu;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3379p2;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class v {
    public final Context a;
    public final ApplicationInfo b;
    public final ArrayList c;
    public final VersionInfoParcel d;
    public final JSONObject e = new JSONObject();
    public final AtomicBoolean f = new AtomicBoolean(false);

    public v(Context context, ArrayList arrayList, VersionInfoParcel versionInfoParcel) {
        this.a = context;
        this.b = context.getApplicationInfo();
        this.c = arrayList;
        this.d = versionInfoParcel;
    }

    public final JSONObject a() throws JSONException {
        if (!this.f.get()) {
            b(null);
        }
        return this.e;
    }

    public final void b(WebView webView) throws JSONException {
        if (this.f.getAndSet(true)) {
            return;
        }
        ApplicationInfo applicationInfo = this.b;
        PackageInfo packageInfoC = null;
        if (applicationInfo != null) {
            try {
                packageInfoC = com.google.android.gms.common.wrappers.c.a(this.a).c(applicationInfo.packageName, 0);
            } catch (PackageManager.NameNotFoundException unused) {
            }
        }
        JSONObject jSONObject = this.e;
        if (packageInfoC != null) {
            try {
                jSONObject.put("vc", packageInfoC.versionCode);
                jSONObject.put("vnm", packageInfoC.versionName);
            } catch (JSONException e) {
                com.google.android.gms.ads.internal.j.C.h.h("PawAppSignalGenerator.initialize", e);
            }
        }
        if (applicationInfo != null) {
            jSONObject.put("pn", applicationInfo.packageName);
        }
        ArrayList arrayList = this.c;
        ArrayList arrayList2 = new ArrayList();
        for (String str : ((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.O9)).split(",", -1)) {
            if (arrayList.contains(str)) {
                arrayList2.add(str);
            }
        }
        jSONObject.put("eid", arrayList2);
        jSONObject.put("js", this.d.a);
        Iterator<String> itKeys = jSONObject.keys();
        while (itKeys.hasNext()) {
            String next = itKeys.next();
            Object obj = jSONObject.get(next);
            if (obj != null) {
                jSONObject.put(next, Base64.encodeToString(obj.toString().getBytes(), 2));
            }
        }
        if (((Boolean) AbstractC1911c8.b.o()).booleanValue() && AbstractC3379p2.c("DOCUMENT_START_SCRIPT") && webView != null) {
            String str2 = String.format(Locale.getDefault(), (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.N9), a());
            int i = AbstractC2459ou.c;
            Nu nu = new Nu("*");
            int i2 = androidx.webkit.i.a;
            if (!androidx.webkit.internal.s.f.b()) {
                throw androidx.webkit.internal.s.a();
            }
        }
    }
}
