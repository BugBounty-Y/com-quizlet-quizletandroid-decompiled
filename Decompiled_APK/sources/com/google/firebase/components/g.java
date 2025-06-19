package com.google.firebase.components;

import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3561x4;
import com.google.android.gms.internal.mlkit_vision_common.y4;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class g implements b {
    public static final f h = new f(0);
    public final k e;
    public final e g;
    public final HashMap a = new HashMap();
    public final HashMap b = new HashMap();
    public final HashMap c = new HashMap();
    public final HashSet d = new HashSet();
    public final AtomicReference f = new AtomicReference();

    public g(Executor executor, ArrayList arrayList, ArrayList arrayList2, e eVar) {
        k kVar = new k(executor);
        this.e = kVar;
        this.g = eVar;
        ArrayList arrayList3 = new ArrayList();
        arrayList3.add(a.c(kVar, k.class, com.google.firebase.events.c.class, com.google.firebase.events.b.class));
        arrayList3.add(a.c(this, g.class, new Class[0]));
        Iterator it2 = arrayList2.iterator();
        while (it2.hasNext()) {
            a aVar = (a) it2.next();
            if (aVar != null) {
                arrayList3.add(aVar);
            }
        }
        ArrayList arrayList4 = new ArrayList();
        Iterator it3 = arrayList.iterator();
        while (it3.hasNext()) {
            arrayList4.add(it3.next());
        }
        ArrayList arrayList5 = new ArrayList();
        synchronized (this) {
            Iterator it4 = arrayList4.iterator();
            while (it4.hasNext()) {
                try {
                    ComponentRegistrar componentRegistrar = (ComponentRegistrar) ((com.google.firebase.inject.b) it4.next()).get();
                    if (componentRegistrar != null) {
                        arrayList3.addAll(this.g.a(componentRegistrar));
                        it4.remove();
                    }
                } catch (InvalidRegistrarException e) {
                    it4.remove();
                    Log.w("ComponentDiscovery", "Invalid component registrar.", e);
                }
            }
            Iterator it5 = arrayList3.iterator();
            while (it5.hasNext()) {
                Object[] array = ((a) it5.next()).b.toArray();
                int length = array.length;
                int i = 0;
                while (true) {
                    if (i < length) {
                        Object obj = array[i];
                        if (obj.toString().contains("kotlinx.coroutines.CoroutineDispatcher")) {
                            if (this.d.contains(obj.toString())) {
                                it5.remove();
                                break;
                            }
                            this.d.add(obj.toString());
                        }
                        i++;
                    }
                }
            }
            if (this.a.isEmpty()) {
                AbstractC3561x4.d(arrayList3);
            } else {
                ArrayList arrayList6 = new ArrayList(this.a.keySet());
                arrayList6.addAll(arrayList3);
                AbstractC3561x4.d(arrayList6);
            }
            Iterator it6 = arrayList3.iterator();
            while (it6.hasNext()) {
                a aVar2 = (a) it6.next();
                this.a.put(aVar2, new l(new com.google.firebase.d(1, this, aVar2)));
            }
            arrayList5.addAll(j(arrayList3));
            arrayList5.addAll(k());
            i();
        }
        Iterator it7 = arrayList5.iterator();
        while (it7.hasNext()) {
            ((Runnable) it7.next()).run();
        }
        Boolean bool = (Boolean) this.f.get();
        if (bool != null) {
            d(this.a, bool.booleanValue());
        }
    }

    @Override // com.google.firebase.components.b
    public final synchronized com.google.firebase.inject.b a(q qVar) {
        y4.b(qVar, "Null interface requested.");
        return (com.google.firebase.inject.b) this.b.get(qVar);
    }

    public final void d(HashMap map, boolean z) {
        ArrayDeque arrayDeque;
        for (Map.Entry entry : map.entrySet()) {
            a aVar = (a) entry.getKey();
            com.google.firebase.inject.b bVar = (com.google.firebase.inject.b) entry.getValue();
            int i = aVar.d;
            if (i == 1 || (i == 2 && z)) {
                bVar.get();
            }
        }
        k kVar = this.e;
        synchronized (kVar) {
            arrayDeque = kVar.b;
            if (arrayDeque != null) {
                kVar.b = null;
            } else {
                arrayDeque = null;
            }
        }
        if (arrayDeque != null) {
            Iterator it2 = arrayDeque.iterator();
            if (it2.hasNext()) {
                throw android.support.v4.media.session.a.d(it2);
            }
        }
    }

    @Override // com.google.firebase.components.b
    public final synchronized com.google.firebase.inject.b e(q qVar) {
        m mVar = (m) this.c.get(qVar);
        if (mVar != null) {
            return mVar;
        }
        return h;
    }

    @Override // com.google.firebase.components.b
    public final o g(q qVar) {
        com.google.firebase.inject.b bVarA = a(qVar);
        return bVarA == null ? new o(o.c, o.d) : bVarA instanceof o ? (o) bVarA : new o(null, bVarA);
    }

    public final void h(boolean z) {
        HashMap map;
        AtomicReference atomicReference = this.f;
        Boolean boolValueOf = Boolean.valueOf(z);
        while (!atomicReference.compareAndSet(null, boolValueOf)) {
            if (atomicReference.get() != null) {
                return;
            }
        }
        synchronized (this) {
            map = new HashMap(this.a);
        }
        d(map, z);
    }

    public final void i() {
        for (a aVar : this.a.keySet()) {
            for (j jVar : aVar.c) {
                boolean z = jVar.b == 2;
                q qVar = jVar.a;
                if (z) {
                    HashMap map = this.c;
                    if (!map.containsKey(qVar)) {
                        Set set = Collections.EMPTY_SET;
                        m mVar = new m();
                        mVar.b = null;
                        mVar.a = Collections.newSetFromMap(new ConcurrentHashMap());
                        mVar.a.addAll(set);
                        map.put(qVar, mVar);
                    }
                }
                HashMap map2 = this.b;
                if (map2.containsKey(qVar)) {
                    continue;
                } else {
                    int i = jVar.b;
                    if (i == 1) {
                        throw new MissingDependencyException("Unsatisfied dependency for component " + aVar + ": " + qVar);
                    }
                    if (i != 2) {
                        map2.put(qVar, new o(o.c, o.d));
                    }
                }
            }
        }
    }

    public final ArrayList j(ArrayList arrayList) {
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            a aVar = (a) it2.next();
            if (aVar.e == 0) {
                com.google.firebase.inject.b bVar = (com.google.firebase.inject.b) this.a.get(aVar);
                for (q qVar : aVar.b) {
                    HashMap map = this.b;
                    if (map.containsKey(qVar)) {
                        arrayList2.add(new androidx.credentials.playservices.controllers.c(26, (o) ((com.google.firebase.inject.b) map.get(qVar)), bVar));
                    } else {
                        map.put(qVar, bVar);
                    }
                }
            }
        }
        return arrayList2;
    }

    public final ArrayList k() {
        ArrayList arrayList = new ArrayList();
        HashMap map = new HashMap();
        for (Map.Entry entry : this.a.entrySet()) {
            a aVar = (a) entry.getKey();
            if (aVar.e != 0) {
                com.google.firebase.inject.b bVar = (com.google.firebase.inject.b) entry.getValue();
                for (q qVar : aVar.b) {
                    if (!map.containsKey(qVar)) {
                        map.put(qVar, new HashSet());
                    }
                    ((Set) map.get(qVar)).add(bVar);
                }
            }
        }
        for (Map.Entry entry2 : map.entrySet()) {
            Object key = entry2.getKey();
            HashMap map2 = this.c;
            if (map2.containsKey(key)) {
                m mVar = (m) map2.get(entry2.getKey());
                Iterator it2 = ((Set) entry2.getValue()).iterator();
                while (it2.hasNext()) {
                    arrayList.add(new androidx.credentials.playservices.controllers.c(27, mVar, (com.google.firebase.inject.b) it2.next()));
                }
            } else {
                q qVar2 = (q) entry2.getKey();
                Set set = (Set) ((Collection) entry2.getValue());
                m mVar2 = new m();
                mVar2.b = null;
                mVar2.a = Collections.newSetFromMap(new ConcurrentHashMap());
                mVar2.a.addAll(set);
                map2.put(qVar2, mVar2);
            }
        }
        return arrayList;
    }
}
