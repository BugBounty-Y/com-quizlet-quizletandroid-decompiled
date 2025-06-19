package com.pubmatic.sdk.common.cache;

import com.pubmatic.sdk.common.cache.b;

/* loaded from: classes2.dex */
public class c implements Runnable {
    final /* synthetic */ String a;
    final /* synthetic */ b.a b;

    public c(b.a aVar, String str) {
        this.b = aVar;
        this.a = str;
    }

    @Override // java.lang.Runnable
    public void run() {
        b.a aVar;
        com.pubmatic.sdk.common.viewability.c cVar;
        synchronized (b.this.g) {
            try {
                b.this.f = this.a;
                if (b.this.f != null && (cVar = (aVar = this.b).a) != null) {
                    cVar.onMeasurementScriptReceived(b.this.f);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
