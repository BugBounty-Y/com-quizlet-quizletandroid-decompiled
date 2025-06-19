package org.slf4j.helpers;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;

/* loaded from: classes3.dex */
public final class i implements org.slf4j.a {
    public volatile boolean a = false;
    public final ConcurrentHashMap b = new ConcurrentHashMap();
    public final LinkedBlockingQueue c = new LinkedBlockingQueue();

    @Override // org.slf4j.a
    public final synchronized org.slf4j.b a(String str) {
        h hVar;
        hVar = (h) this.b.get(str);
        if (hVar == null) {
            hVar = new h(str, this.c, this.a);
            this.b.put(str, hVar);
        }
        return hVar;
    }
}
