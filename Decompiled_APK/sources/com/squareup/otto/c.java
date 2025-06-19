package com.squareup.otto;

import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes3.dex */
public final class c {
    public final ConcurrentHashMap a;
    public final ConcurrentHashMap b;
    public final String c;
    public final g d;
    public final g e;
    public final androidx.camera.core.impl.utils.executor.b f;
    public final androidx.camera.core.impl.utils.executor.b g;
    public final ConcurrentHashMap h;

    public c() {
        g gVar = g.b;
        g gVar2 = g.a;
        this.a = new ConcurrentHashMap();
        this.b = new ConcurrentHashMap();
        this.f = new androidx.camera.core.impl.utils.executor.b(17);
        this.g = new androidx.camera.core.impl.utils.executor.b(18);
        this.h = new ConcurrentHashMap();
        this.d = gVar;
        this.c = "default";
        this.e = gVar2;
    }

    public static void a(Object obj, e eVar) throws IllegalAccessException, IllegalArgumentException {
        try {
            eVar.a(obj);
        } catch (InvocationTargetException e) {
            e("Could not dispatch event: " + obj.getClass() + " to handler " + eVar, e);
            throw null;
        }
    }

    public static void b(e eVar, f fVar) throws IllegalAccessException, IllegalArgumentException {
        try {
            Object objA = fVar.a();
            if (objA == null) {
                return;
            }
            a(objA, eVar);
        } catch (InvocationTargetException e) {
            e("Producer " + fVar + " threw an exception.", e);
            throw null;
        }
    }

    public static void e(String str, InvocationTargetException invocationTargetException) {
        Throwable cause = invocationTargetException.getCause();
        if (cause != null) {
            StringBuilder sbX = android.support.v4.media.session.a.x(str, ": ");
            sbX.append(cause.getMessage());
            throw new RuntimeException(sbX.toString(), cause);
        }
        StringBuilder sbX2 = android.support.v4.media.session.a.x(str, ": ");
        sbX2.append(invocationTargetException.getMessage());
        throw new RuntimeException(sbX2.toString(), invocationTargetException);
    }

    public final void c(Object obj) {
        androidx.camera.core.impl.utils.executor.b bVar;
        this.d.a(this);
        Class<?> cls = obj.getClass();
        ConcurrentHashMap concurrentHashMap = this.h;
        Set set = (Set) concurrentHashMap.get(cls);
        boolean z = false;
        if (set == null) {
            LinkedList linkedList = new LinkedList();
            HashSet hashSet = new HashSet();
            linkedList.add(cls);
            while (!linkedList.isEmpty()) {
                Class cls2 = (Class) linkedList.remove(0);
                hashSet.add(cls2);
                Class superclass = cls2.getSuperclass();
                if (superclass != null) {
                    linkedList.add(superclass);
                }
            }
            set = (Set) concurrentHashMap.putIfAbsent(cls, hashSet);
            if (set == null) {
                set = hashSet;
            }
        }
        Iterator it2 = set.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            bVar = this.f;
            if (!zHasNext) {
                break;
            }
            Set set2 = (Set) this.a.get((Class) it2.next());
            if (set2 != null && !set2.isEmpty()) {
                Iterator it3 = set2.iterator();
                while (it3.hasNext()) {
                    ((ConcurrentLinkedQueue) bVar.get()).offer(new b(obj, (e) it3.next()));
                }
                z = true;
            }
        }
        if (!z && !(obj instanceof d)) {
            c(new d(this, obj));
        }
        androidx.camera.core.impl.utils.executor.b bVar2 = this.g;
        if (((Boolean) bVar2.get()).booleanValue()) {
            return;
        }
        bVar2.set(Boolean.TRUE);
        while (true) {
            try {
                b bVar3 = (b) ((ConcurrentLinkedQueue) bVar.get()).poll();
                if (bVar3 == null) {
                    return;
                }
                e eVar = bVar3.b;
                if (eVar.d) {
                    a(bVar3.a, eVar);
                }
            } finally {
                bVar2.set(Boolean.FALSE);
            }
        }
    }

    public final void d(Object obj) throws IllegalAccessException, SecurityException, IllegalArgumentException {
        if (obj == null) {
            throw new NullPointerException("Object to register must not be null.");
        }
        this.d.a(this);
        g gVar = this.e;
        HashMap mapB = gVar.b(obj);
        Iterator it2 = mapB.keySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            ConcurrentHashMap concurrentHashMap = this.b;
            ConcurrentHashMap concurrentHashMap2 = this.a;
            if (!zHasNext) {
                HashMap mapC = gVar.c(obj);
                for (Class cls : mapC.keySet()) {
                    Set copyOnWriteArraySet = (Set) concurrentHashMap2.get(cls);
                    if (copyOnWriteArraySet == null) {
                        copyOnWriteArraySet = new CopyOnWriteArraySet();
                        Set set = (Set) concurrentHashMap2.putIfAbsent(cls, copyOnWriteArraySet);
                        if (set != null) {
                            copyOnWriteArraySet = set;
                        }
                    }
                    if (!copyOnWriteArraySet.addAll((Set) mapC.get(cls))) {
                        throw new IllegalArgumentException("Object already registered.");
                    }
                }
                for (Map.Entry entry : mapC.entrySet()) {
                    f fVar = (f) concurrentHashMap.get((Class) entry.getKey());
                    if (fVar != null && fVar.d) {
                        for (e eVar : (Set) entry.getValue()) {
                            if (!fVar.d) {
                                break;
                            } else if (eVar.d) {
                                b(eVar, fVar);
                            }
                        }
                    }
                }
                return;
            }
            Class cls2 = (Class) it2.next();
            f fVar2 = (f) mapB.get(cls2);
            f fVar3 = (f) concurrentHashMap.putIfAbsent(cls2, fVar2);
            if (fVar3 != null) {
                throw new IllegalArgumentException("Producer method for type " + cls2 + " found on type " + fVar2.a.getClass() + ", but already registered by type " + fVar3.a.getClass() + ".");
            }
            Set set2 = (Set) concurrentHashMap2.get(cls2);
            if (set2 != null && !set2.isEmpty()) {
                Iterator it3 = set2.iterator();
                while (it3.hasNext()) {
                    b((e) it3.next(), fVar2);
                }
            }
        }
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("[Bus \""), this.c, "\"]");
    }
}
