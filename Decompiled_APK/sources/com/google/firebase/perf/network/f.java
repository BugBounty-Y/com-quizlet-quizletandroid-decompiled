package com.google.firebase.perf.network;

import com.google.firebase.perf.util.Timer;
import org.apache.http.HttpResponse;
import org.apache.http.client.ResponseHandler;

/* loaded from: classes2.dex */
public final class f implements ResponseHandler {
    public final ResponseHandler a;
    public final Timer b;
    public final com.google.firebase.perf.metrics.d c;

    public f(ResponseHandler responseHandler, Timer timer, com.google.firebase.perf.metrics.d dVar) {
        this.a = responseHandler;
        this.b = timer;
        this.c = dVar;
    }

    @Override // org.apache.http.client.ResponseHandler
    public final Object handleResponse(HttpResponse httpResponse) {
        this.c.j(this.b.a());
        this.c.d(httpResponse.getStatusLine().getStatusCode());
        Long lA = g.a(httpResponse);
        if (lA != null) {
            this.c.i(lA.longValue());
        }
        String strB = g.b(httpResponse);
        if (strB != null) {
            this.c.h(strB);
        }
        this.c.b();
        return this.a.handleResponse(httpResponse);
    }
}
