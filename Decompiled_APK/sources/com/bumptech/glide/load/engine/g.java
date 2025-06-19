package com.bumptech.glide.load.engine;

import androidx.collection.C0203a;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes.dex */
public final class g {
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public com.bumptech.glide.e c;
    public Object d;
    public int e;
    public int f;
    public Class g;
    public k h;
    public com.bumptech.glide.load.h i;
    public com.bumptech.glide.util.c j;
    public Class k;
    public boolean l;
    public boolean m;
    public com.bumptech.glide.load.e n;
    public com.bumptech.glide.g o;
    public j p;
    public boolean q;
    public boolean r;

    public final ArrayList a() {
        boolean z = this.m;
        ArrayList arrayList = this.b;
        if (!z) {
            this.m = true;
            arrayList.clear();
            ArrayList arrayListB = b();
            int size = arrayListB.size();
            for (int i = 0; i < size; i++) {
                com.bumptech.glide.load.model.q qVar = (com.bumptech.glide.load.model.q) arrayListB.get(i);
                if (!arrayList.contains(qVar.a)) {
                    arrayList.add(qVar.a);
                }
                int i2 = 0;
                while (true) {
                    List list = qVar.b;
                    if (i2 < list.size()) {
                        if (!arrayList.contains(list.get(i2))) {
                            arrayList.add(list.get(i2));
                        }
                        i2++;
                    }
                }
            }
        }
        return arrayList;
    }

    public final ArrayList b() {
        boolean z = this.l;
        ArrayList arrayList = this.a;
        if (!z) {
            this.l = true;
            arrayList.clear();
            List listF = this.c.a().f(this.d);
            int size = listF.size();
            for (int i = 0; i < size; i++) {
                com.bumptech.glide.load.model.q qVarB = ((com.bumptech.glide.load.model.r) listF.get(i)).b(this.d, this.e, this.f, this.i);
                if (qVarB != null) {
                    arrayList.add(qVarB);
                }
            }
        }
        return arrayList;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final t c(Class cls) {
        t tVar;
        Class cls2;
        Class cls3;
        Class cls4;
        t tVar2;
        ArrayList arrayList;
        com.bumptech.glide.load.resource.transcode.b bVar;
        Class cls5 = cls;
        com.bumptech.glide.h hVarA = this.c.a();
        Class cls6 = this.g;
        Class cls7 = this.k;
        com.bumptech.glide.provider.b bVar2 = hVarA.i;
        com.bumptech.glide.util.k kVar = (com.bumptech.glide.util.k) bVar2.b.getAndSet(null);
        if (kVar == null) {
            kVar = new com.bumptech.glide.util.k();
        }
        kVar.a = cls5;
        kVar.b = cls6;
        kVar.c = cls7;
        synchronized (bVar2.a) {
            tVar = (t) bVar2.a.get(kVar);
        }
        bVar2.b.set(kVar);
        hVarA.i.getClass();
        if (com.bumptech.glide.provider.b.c.equals(tVar)) {
            return null;
        }
        if (tVar != null) {
            return tVar;
        }
        ArrayList arrayList2 = new ArrayList();
        Iterator it2 = hVarA.c.f(cls5, cls6).iterator();
        while (it2.hasNext()) {
            Class<?> cls8 = (Class) it2.next();
            Iterator it3 = hVarA.f.e(cls8, cls7).iterator();
            while (it3.hasNext()) {
                Class cls9 = (Class) it3.next();
                androidx.work.impl.model.v vVar = hVarA.c;
                synchronized (vVar) {
                    arrayList = new ArrayList();
                    Iterator it4 = ((ArrayList) vVar.b).iterator();
                    while (it4.hasNext()) {
                        List<com.bumptech.glide.provider.c> list = (List) ((HashMap) vVar.c).get((String) it4.next());
                        if (list != null) {
                            for (com.bumptech.glide.provider.c cVar : list) {
                                if (cVar.a.isAssignableFrom(cls5) && cls8.isAssignableFrom(cVar.b)) {
                                    arrayList.add(cVar.c);
                                }
                            }
                        }
                    }
                }
                com.android.billingclient.api.h hVar = hVarA.f;
                synchronized (hVar) {
                    if (!cls9.isAssignableFrom(cls8)) {
                        Iterator it5 = hVar.a.iterator();
                        while (it5.hasNext()) {
                            com.bumptech.glide.load.resource.transcode.c cVar2 = (com.bumptech.glide.load.resource.transcode.c) it5.next();
                            if (cVar2.a.isAssignableFrom(cls8) && cls9.isAssignableFrom(cVar2.b)) {
                                bVar = cVar2.c;
                            } else {
                                cls5 = cls;
                            }
                        }
                        throw new IllegalArgumentException("No transcoder registered to transcode from " + cls8 + " to " + cls9);
                    }
                    bVar = com.bumptech.glide.load.resource.transcode.d.b;
                }
                arrayList2.add(new i(cls5, cls8, cls9, arrayList, bVar, hVarA.j));
                cls5 = cls;
            }
            cls5 = cls;
        }
        if (arrayList2.isEmpty()) {
            cls2 = cls;
            cls3 = cls6;
            cls4 = cls7;
            tVar2 = null;
        } else {
            cls2 = cls;
            cls3 = cls6;
            cls4 = cls7;
            tVar2 = new t(cls2, cls3, cls4, arrayList2, hVarA.j);
        }
        com.bumptech.glide.provider.b bVar3 = hVarA.i;
        synchronized (bVar3.a) {
            bVar3.a.put(new com.bumptech.glide.util.k(cls2, cls3, cls4), tVar2 != null ? tVar2 : com.bumptech.glide.provider.b.c);
        }
        return tVar2;
    }

    /* JADX WARN: Code restructure failed: missing block: B:9:0x0027, code lost:
    
        r1 = r3.b;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.bumptech.glide.load.b d(java.lang.Object r6) {
        /*
            r5 = this;
            com.bumptech.glide.e r0 = r5.c
            com.bumptech.glide.h r0 = r0.a()
            androidx.compose.ui.graphics.vector.g r0 = r0.b
            java.lang.Class r1 = r6.getClass()
            monitor-enter(r0)
            java.util.ArrayList r2 = r0.a     // Catch: java.lang.Throwable -> L2b
            java.util.Iterator r2 = r2.iterator()     // Catch: java.lang.Throwable -> L2b
        L13:
            boolean r3 = r2.hasNext()     // Catch: java.lang.Throwable -> L2b
            if (r3 == 0) goto L2d
            java.lang.Object r3 = r2.next()     // Catch: java.lang.Throwable -> L2b
            com.bumptech.glide.provider.a r3 = (com.bumptech.glide.provider.a) r3     // Catch: java.lang.Throwable -> L2b
            java.lang.Class r4 = r3.a     // Catch: java.lang.Throwable -> L2b
            boolean r4 = r4.isAssignableFrom(r1)     // Catch: java.lang.Throwable -> L2b
            if (r4 == 0) goto L13
            com.bumptech.glide.load.b r1 = r3.b     // Catch: java.lang.Throwable -> L2b
            monitor-exit(r0)
            goto L2f
        L2b:
            r6 = move-exception
            goto L42
        L2d:
            monitor-exit(r0)
            r1 = 0
        L2f:
            if (r1 == 0) goto L32
            return r1
        L32:
            com.bumptech.glide.Registry$NoSourceEncoderAvailableException r0 = new com.bumptech.glide.Registry$NoSourceEncoderAvailableException
            java.lang.Class r6 = r6.getClass()
            java.lang.String r1 = "Failed to find source encoder for data class: "
            java.lang.String r6 = androidx.compose.ui.node.B.d(r6, r1)
            r0.<init>(r6)
            throw r0
        L42:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L2b
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.bumptech.glide.load.engine.g.d(java.lang.Object):com.bumptech.glide.load.b");
    }

    public final com.bumptech.glide.load.l e(Class cls) {
        com.bumptech.glide.load.l lVar = (com.bumptech.glide.load.l) this.j.get(cls);
        if (lVar == null) {
            Iterator it2 = ((C0203a) this.j.entrySet()).iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                Map.Entry entry = (Map.Entry) it2.next();
                if (((Class) entry.getKey()).isAssignableFrom(cls)) {
                    lVar = (com.bumptech.glide.load.l) entry.getValue();
                    break;
                }
            }
        }
        if (lVar != null) {
            return lVar;
        }
        if (!this.j.isEmpty() || !this.q) {
            return com.bumptech.glide.load.resource.d.b;
        }
        throw new IllegalArgumentException("Missing transformation for " + cls + ". If you wish to ignore unknown resource types, use the optional transformation methods.");
    }
}
