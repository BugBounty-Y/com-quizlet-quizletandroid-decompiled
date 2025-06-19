package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public final class Ag implements InterfaceC1582a {
    public final Dg a;
    public final C2023eq b;

    public Ag(Dg dg, C2023eq c2023eq) {
        this.a = dg;
        this.b = c2023eq;
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        C2023eq c2023eq = this.b;
        Dg dg = this.a;
        String str = c2023eq.f;
        synchronized (dg.a) {
            try {
                ConcurrentHashMap concurrentHashMap = dg.b;
                Integer num = (Integer) concurrentHashMap.get(str);
                concurrentHashMap.put(str, num == null ? 1 : Integer.valueOf(num.intValue() + 1));
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
