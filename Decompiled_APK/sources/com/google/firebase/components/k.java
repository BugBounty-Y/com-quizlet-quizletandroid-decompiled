package com.google.firebase.components;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class k implements com.google.firebase.events.c, com.google.firebase.events.b {
    public final HashMap a = new HashMap();
    public ArrayDeque b = new ArrayDeque();
    public final Executor c;

    public k(Executor executor) {
        this.c = executor;
    }

    public final synchronized void a(Executor executor, com.google.firebase.events.a aVar) {
        try {
            executor.getClass();
            if (!this.a.containsKey(com.google.firebase.b.class)) {
                this.a.put(com.google.firebase.b.class, new ConcurrentHashMap());
            }
            ((ConcurrentHashMap) this.a.get(com.google.firebase.b.class)).put(aVar, executor);
        } catch (Throwable th) {
            throw th;
        }
    }

    public final synchronized void b(n nVar) {
        nVar.getClass();
        if (this.a.containsKey(com.google.firebase.b.class)) {
            ConcurrentHashMap concurrentHashMap = (ConcurrentHashMap) this.a.get(com.google.firebase.b.class);
            concurrentHashMap.remove(nVar);
            if (concurrentHashMap.isEmpty()) {
                this.a.remove(com.google.firebase.b.class);
            }
        }
    }
}
