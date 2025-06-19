package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2601s7;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.ads.internal.util.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC1626b implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C1633i b;

    public /* synthetic */ RunnableC1626b(C1633i c1633i, int i) {
        this.a = i;
        this.b = c1633i;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                C1633i c1633i = this.b;
                c1633i.c(c1633i.a);
                return;
            case 1:
                C1633i c1633i2 = this.b;
                c1633i2.g = 4;
                c1633i2.b();
                return;
            case 2:
                C1633i c1633i3 = this.b;
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                androidx.camera.camera2.interop.c cVar = jVar.o;
                Context context = c1633i3.a;
                String str = c1633i3.d;
                String str2 = c1633i3.e;
                cVar.getClass();
                C2601s7 c2601s7 = AbstractC2773w7.T4;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                String strJ = androidx.camera.camera2.interop.c.j(context, cVar.k(context, (String) rVar.c.a(c2601s7), str, str2).toString(), str2);
                if (TextUtils.isEmpty(strJ)) {
                    com.google.android.gms.ads.internal.util.client.i.d("Not linked for in app preview.");
                } else {
                    try {
                        JSONObject jSONObject = new JSONObject(strJ.trim());
                        String strOptString = jSONObject.optString("gct");
                        cVar.f = jSONObject.optString("status");
                        if (((Boolean) rVar.c.a(AbstractC2773w7.j9)).booleanValue()) {
                            boolean z = "0".equals((String) cVar.f) || "2".equals((String) cVar.f);
                            cVar.d(z);
                            jVar.h.d().q(!z ? "" : str);
                        }
                        synchronized (cVar.a) {
                            cVar.e = strOptString;
                        }
                        if ("2".equals((String) cVar.f)) {
                            com.google.android.gms.ads.internal.util.client.i.d("Creative is not pushed for this device.");
                            androidx.camera.camera2.interop.c.e(context, "There was no creative pushed from DFP to the device.", false, false);
                            return;
                        } else if ("1".equals((String) cVar.f)) {
                            com.google.android.gms.ads.internal.util.client.i.d("The app is not linked for creative preview.");
                            cVar.b(context, str, str2);
                            return;
                        } else {
                            if ("0".equals((String) cVar.f)) {
                                com.google.android.gms.ads.internal.util.client.i.d("Device is linked for in app preview.");
                                androidx.camera.camera2.interop.c.e(context, "The device is successfully linked for creative preview.", false, true);
                                return;
                            }
                            return;
                        }
                    } catch (JSONException e) {
                        com.google.android.gms.ads.internal.util.client.i.i("Fail to get in app preview response json.", e);
                    }
                }
                androidx.camera.camera2.interop.c.e(context, "In-app preview failed to load because of a system error. Please try again later.", true, true);
                return;
            case 3:
                com.google.android.gms.ads.internal.j.C.o.a(this.b.a);
                return;
            case 4:
                C1633i c1633i4 = this.b;
                c1633i4.c(c1633i4.a);
                return;
            case 5:
                com.google.android.gms.ads.internal.j.C.o.a(this.b.a);
                return;
            default:
                C1633i c1633i5 = this.b;
                androidx.camera.camera2.interop.c cVar2 = com.google.android.gms.ads.internal.j.C.o;
                String str3 = c1633i5.d;
                String str4 = c1633i5.e;
                String str5 = c1633i5.f;
                boolean zH = cVar2.h();
                Context context2 = c1633i5.a;
                boolean zF = cVar2.f(context2, str3, str4);
                synchronized (cVar2.a) {
                    cVar2.b = zF;
                }
                if (!cVar2.h()) {
                    cVar2.b(context2, str3, str4);
                    return;
                }
                if (!zH && !TextUtils.isEmpty(str5)) {
                    cVar2.c(context2, str4, str5, str3);
                }
                com.google.android.gms.ads.internal.util.client.i.d("Device is linked for debug signals.");
                androidx.camera.camera2.interop.c.e(context2, "The device is successfully linked for troubleshooting.", false, true);
                return;
        }
    }
}
