package com.google.android.gms.ads.nonagon.signalgeneration;

import android.util.Pair;
import java.util.LinkedHashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class D extends LinkedHashMap {
    public final /* synthetic */ F a;

    public D(F f) {
        this.a = f;
    }

    @Override // java.util.LinkedHashMap
    public final boolean removeEldestEntry(Map.Entry entry) {
        F f = this.a;
        synchronized (f) {
            try {
                if (size() <= f.a) {
                    return false;
                }
                f.f.add(new Pair((String) entry.getKey(), ((E) entry.getValue()).b));
                return size() > f.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
