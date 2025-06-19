package com.google.android.gms.ads.nonagon.signalgeneration;

import android.annotation.TargetApi;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Pair;
import android.view.MotionEvent;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import androidx.annotation.NonNull;
import androidx.appcompat.app.L;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdRequest$Builder;
import com.google.android.gms.internal.ads.AbstractC1911c8;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C2067fq;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2584rr;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.Kk;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.ads.nonagon.signalgeneration.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1635a {
    public final Context a;
    public final WebView b;
    public final P4 c;
    public final C2067fq d;
    public final int e;
    public final Kk f;
    public final boolean g;
    public final C2227jd h = AbstractC2270kd.f;
    public final C2584rr i;
    public final A j;
    public final v k;
    public final y l;

    public C1635a(WebView webView, P4 p4, Kk kk, C2584rr c2584rr, C2067fq c2067fq, A a, v vVar, y yVar) {
        this.b = webView;
        Context context = webView.getContext();
        this.a = context;
        this.c = p4;
        this.f = kk;
        AbstractC2773w7.a(context);
        C2601s7 c2601s7 = AbstractC2773w7.D9;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        this.e = ((Integer) rVar.c.a(c2601s7)).intValue();
        this.g = ((Boolean) rVar.c.a(AbstractC2773w7.E9)).booleanValue();
        this.i = c2584rr;
        this.d = c2067fq;
        this.j = a;
        this.k = vVar;
        this.l = yVar;
    }

    @NonNull
    @JavascriptInterface
    @TargetApi(21)
    public String getClickSignals(@NonNull String str) {
        try {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            jVar.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            String strD = this.c.b.d(this.a, this.b, str);
            if (!this.g) {
                return strD;
            }
            jVar.k.getClass();
            AbstractC3429b3.f(this.f, "csg", new Pair("clat", String.valueOf(System.currentTimeMillis() - jCurrentTimeMillis)));
            return strD;
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Exception getting click signals. ", e);
            com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.getClickSignals", e);
            return "";
        }
    }

    @NonNull
    @JavascriptInterface
    @TargetApi(21)
    public String getClickSignalsWithTimeout(@NonNull String str, int i) {
        if (i <= 0) {
            com.google.android.gms.ads.internal.util.client.i.e("Invalid timeout for getting click signals. Timeout=" + i);
            return "";
        }
        try {
            return (String) AbstractC2270kd.a.d(new com.google.android.gms.ads.internal.util.y(3, this, str)).get(Math.min(i, this.e), TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Exception getting click signals with timeout. ", e);
            com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.getClickSignalsWithTimeout", e);
            return e instanceof TimeoutException ? "17" : "";
        }
    }

    @NonNull
    @JavascriptInterface
    @TargetApi(21)
    public String getQueryInfo() {
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        String string = UUID.randomUUID().toString();
        Bundle bundle = new Bundle();
        bundle.putString("query_info_type", "requester_type_6");
        s sVar = new s(string, 0, this);
        if (((Boolean) AbstractC1911c8.e.o()).booleanValue()) {
            this.j.b(this.b, sVar);
            return string;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G9)).booleanValue()) {
            this.h.execute(new androidx.core.provider.k(this, bundle, sVar, 6));
            return string;
        }
        AdRequest$Builder adRequest$Builder = (AdRequest$Builder) new AdRequest$Builder().addNetworkExtrasBundle(AdMobAdapter.class, bundle);
        adRequest$Builder.getClass();
        L.J(this.a, new com.google.android.gms.ads.g(adRequest$Builder), sVar);
        return string;
    }

    @NonNull
    @JavascriptInterface
    @TargetApi(21)
    public String getViewSignals() {
        try {
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            jVar.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            String strI = this.c.b.i(this.a, this.b, null);
            if (!this.g) {
                return strI;
            }
            jVar.k.getClass();
            AbstractC3429b3.f(this.f, "vsg", new Pair("vlat", String.valueOf(System.currentTimeMillis() - jCurrentTimeMillis)));
            return strI;
        } catch (RuntimeException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Exception getting view signals. ", e);
            com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.getViewSignals", e);
            return "";
        }
    }

    @NonNull
    @JavascriptInterface
    @TargetApi(21)
    public String getViewSignalsWithTimeout(int i) {
        if (i <= 0) {
            com.google.android.gms.ads.internal.util.client.i.e("Invalid timeout for getting view signals. Timeout=" + i);
            return "";
        }
        try {
            return (String) AbstractC2270kd.a.d(new androidx.camera.core.impl.utils.executor.c(this, 8)).get(Math.min(i, this.e), TimeUnit.MILLISECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            com.google.android.gms.ads.internal.util.client.i.f("Exception getting view signals with timeout. ", e);
            com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.getViewSignalsWithTimeout", e);
            return e instanceof TimeoutException ? "17" : "";
        }
    }

    @JavascriptInterface
    @TargetApi(21)
    public void recordClick(@NonNull String str) {
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I9)).booleanValue() || TextUtils.isEmpty(str)) {
            return;
        }
        AbstractC2270kd.a.execute(new androidx.camera.core.impl.utils.futures.h(19, this, str));
    }

    @JavascriptInterface
    @TargetApi(21)
    public void reportTouchEvent(@NonNull String str) throws JSONException {
        int i;
        try {
            JSONObject jSONObject = new JSONObject(str);
            int i2 = jSONObject.getInt("x");
            int i3 = jSONObject.getInt("y");
            int i4 = jSONObject.getInt("duration_ms");
            float f = (float) jSONObject.getDouble("force");
            int i5 = jSONObject.getInt(DBUserFields.Names.USER_UPGRADE_TYPE);
            if (i5 != 0) {
                i = 1;
                if (i5 != 1) {
                    i = 2;
                    if (i5 != 2) {
                        i = 3;
                        if (i5 != 3) {
                            i = -1;
                        }
                    }
                }
            } else {
                i = 0;
            }
            try {
                this.c.b.h(MotionEvent.obtain(0L, i4, i, i2, i3, f, 1.0f, 0, 1.0f, 1.0f, 0, 0));
            } catch (RuntimeException e) {
                e = e;
                com.google.android.gms.ads.internal.util.client.i.f("Failed to parse the touch string. ", e);
                com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.reportTouchEvent", e);
            } catch (JSONException e2) {
                e = e2;
                com.google.android.gms.ads.internal.util.client.i.f("Failed to parse the touch string. ", e);
                com.google.android.gms.ads.internal.j.C.h.h("TaggingLibraryJsInterface.reportTouchEvent", e);
            }
        } catch (RuntimeException | JSONException e3) {
            e = e3;
        }
    }
}
