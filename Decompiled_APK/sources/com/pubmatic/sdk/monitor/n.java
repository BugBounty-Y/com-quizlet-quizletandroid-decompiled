package com.pubmatic.sdk.monitor;

import com.pubmatic.sdk.monitor.g;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class n implements Runnable {
    final /* synthetic */ JSONObject a;
    final /* synthetic */ g.c b;

    public n(g.c cVar, JSONObject jSONObject) {
        this.b = cVar;
        this.a = jSONObject;
    }

    @Override // java.lang.Runnable
    public void run() {
        g.a(this.b.a, this.a.optString("body", ""));
    }
}
