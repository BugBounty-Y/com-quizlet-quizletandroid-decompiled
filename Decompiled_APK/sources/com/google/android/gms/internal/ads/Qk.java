package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.SystemClock;
import android.util.JsonWriter;
import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import com.google.android.gms.ads.internal.client.zze;
import java.io.IOException;
import java.io.StringWriter;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class Qk implements com.google.android.gms.ads.admanager.a, Jh, InterfaceC1582a, Xg, InterfaceC2189ih, InterfaceC2231jh, InterfaceC2617sh, InterfaceC1840ah, Mq {
    public final List a;
    public final Nk b;
    public long c;

    public Qk(Nk nk, C1765Re c1765Re) {
        this.b = nk;
        this.a = Collections.singletonList(c1765Re);
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void A(String str) throws IOException {
        I(Kq.class, "onTaskCreated", str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void E(Context context) throws IOException {
        I(InterfaceC2231jh.class, "onResume", context);
    }

    public final void I(Class cls, String str, Object... objArr) throws IOException {
        String simpleName = cls.getSimpleName();
        List list = this.a;
        String strConcat = "Event-".concat(simpleName);
        Nk nk = this.b;
        nk.getClass();
        if (((Boolean) Y7.a.o()).booleanValue()) {
            long jCurrentTimeMillis = nk.a.currentTimeMillis();
            StringWriter stringWriter = new StringWriter();
            JsonWriter jsonWriter = new JsonWriter(stringWriter);
            try {
                jsonWriter.beginObject();
                jsonWriter.name("timestamp").value(jCurrentTimeMillis);
                jsonWriter.name("source").value(strConcat);
                jsonWriter.name("event").value(str);
                jsonWriter.name("components").beginArray();
                Iterator it2 = list.iterator();
                while (it2.hasNext()) {
                    jsonWriter.value(it2.next().toString());
                }
                jsonWriter.endArray();
                jsonWriter.name("params").beginArray();
                int length = objArr.length;
                for (int i = 0; i < length; i++) {
                    Object obj = objArr[i];
                    jsonWriter.value(obj != null ? obj.toString() : null);
                }
                jsonWriter.endArray();
                jsonWriter.endObject();
                jsonWriter.flush();
                jsonWriter.close();
            } catch (IOException e) {
                com.google.android.gms.ads.internal.util.client.i.f("unable to log", e);
            }
            com.google.android.gms.ads.internal.util.client.i.g("AD-DBG ".concat(String.valueOf(stringWriter.toString())));
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() throws IOException {
        I(InterfaceC2189ih.class, "onAdImpression", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() throws IOException {
        I(Xg.class, "onAdClosed", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() throws IOException {
        I(Xg.class, "onAdLeftApplication", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void c(Jq jq, String str) throws IOException {
        I(Kq.class, "onTaskStarted", str);
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void d(Jq jq, String str, Throwable th) throws IOException {
        I(Kq.class, "onTaskFailed", str, th.getClass().getSimpleName());
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() throws IOException {
        I(Xg.class, "onRewardedVideoStarted", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void j(Context context) throws IOException {
        I(InterfaceC2231jh.class, "onDestroy", context);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) throws IOException {
        I(InterfaceC1840ah.class, "onAdFailedToLoad", Integer.valueOf(zzeVar.a), zzeVar.b, zzeVar.c);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void o(Context context) throws IOException {
        I(InterfaceC2231jh.class, "onPause", context);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() throws IOException {
        I(InterfaceC1582a.class, "onAdClicked", new Object[0]);
    }

    @Override // com.google.android.gms.ads.admanager.a
    public final void onAppEvent(String str, String str2) throws IOException {
        I(com.google.android.gms.ads.admanager.a.class, "onAppEvent", str, str2);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() throws IOException {
        I(Xg.class, "onAdOpened", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.Mq
    public final void r(Jq jq, String str) throws IOException {
        I(Kq.class, "onTaskSucceeded", str);
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) throws IOException {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        this.c = SystemClock.elapsedRealtime();
        I(Jh.class, "onAdRequest", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() throws IOException {
        com.google.android.gms.ads.internal.j.C.k.getClass();
        com.google.android.gms.ads.internal.util.A.l("Ad Request Latency : " + (SystemClock.elapsedRealtime() - this.c));
        I(InterfaceC2617sh.class, "onAdLoaded", new Object[0]);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) throws IOException {
        I(Xg.class, "onRewarded", binderC1966dc, str, str2);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() throws IOException {
        I(Xg.class, "onRewardedVideoCompleted", new Object[0]);
    }
}
