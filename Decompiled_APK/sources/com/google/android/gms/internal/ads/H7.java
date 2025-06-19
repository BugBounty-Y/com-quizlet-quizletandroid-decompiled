package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Pair;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class H7 extends androidx.browser.customtabs.a {
    public final AtomicBoolean a = new AtomicBoolean(false);
    public final List b = Arrays.asList(((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T9)).split(","));
    public final I7 c;
    public final androidx.browser.customtabs.a d;
    public final Kk e;

    public H7(I7 i7, androidx.browser.customtabs.a aVar, Kk kk) {
        this.d = aVar;
        this.c = i7;
        this.e = kk;
    }

    @Override // androidx.browser.customtabs.a
    public final void a(Bundle bundle, String str) {
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.a(bundle, str);
        }
    }

    @Override // androidx.browser.customtabs.a
    public final Bundle b(Bundle bundle, String str) {
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            return aVar.b(bundle, str);
        }
        return null;
    }

    @Override // androidx.browser.customtabs.a
    public final void c(int i, int i2, Bundle bundle) {
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.c(i, i2, bundle);
        }
    }

    @Override // androidx.browser.customtabs.a
    public final void d(Bundle bundle) {
        this.a.set(false);
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.d(bundle);
        }
    }

    @Override // androidx.browser.customtabs.a
    public final void e(int i, Bundle bundle) {
        this.a.set(false);
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.e(i, bundle);
        }
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        I7 i7 = this.c;
        i7.j = jCurrentTimeMillis;
        List list = this.b;
        if (list == null || !list.contains(String.valueOf(i))) {
            return;
        }
        jVar.k.getClass();
        i7.i = SystemClock.elapsedRealtime() + ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Q9)).intValue();
        if (i7.e == null) {
            i7.e = new RunnableC1989e(i7, 12);
        }
        i7.d();
        AbstractC3429b3.f(this.e, "pact_action", new Pair("pe", "pact_reqpmc"));
    }

    @Override // androidx.browser.customtabs.a
    public final void f(Bundle bundle, String str) {
        try {
            JSONObject jSONObject = new JSONObject(str);
            if (jSONObject.optInt("gpa", -1) == 0) {
                this.a.set(true);
                AbstractC3429b3.f(this.e, "pact_action", new Pair("pe", "pact_con"));
                this.c.c(jSONObject.getString("paw_id"));
            }
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.A.m();
        }
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.f(bundle, str);
        }
    }

    @Override // androidx.browser.customtabs.a
    public final void g(int i, Uri uri, boolean z, Bundle bundle) {
        androidx.browser.customtabs.a aVar = this.d;
        if (aVar != null) {
            aVar.g(i, uri, z, bundle);
        }
    }
}
