package com.pubmatic.sdk.monitor;

import com.pubmatic.sdk.monitor.POBMonitor;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class l implements Runnable {
    final /* synthetic */ JSONObject a;
    final /* synthetic */ POBMonitor.c b;

    public l(POBMonitor.c cVar, JSONObject jSONObject) {
        this.b = cVar;
        this.a = jSONObject;
    }

    @Override // java.lang.Runnable
    public void run() {
        if (POBMonitor.this.webView != null) {
            POBMonitor.this.webView.appendData(this.a);
        }
    }
}
