package com.bumptech.glide.load.engine;

import androidx.collection.C0208f;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class w implements f, com.bumptech.glide.load.data.d {
    public final h a;
    public final g b;
    public int c;
    public int d = -1;
    public com.bumptech.glide.load.e e;
    public List f;
    public int g;
    public volatile com.bumptech.glide.load.model.q h;
    public File i;
    public x j;

    public w(g gVar, h hVar) {
        this.b = gVar;
        this.a = hVar;
    }

    @Override // com.bumptech.glide.load.data.d
    public final void a(Exception exc) {
        this.a.c(this.j, exc, this.h.c, 4);
    }

    @Override // com.bumptech.glide.load.engine.f
    public final boolean b() {
        List list;
        ArrayList arrayListD;
        ArrayList arrayListA = this.b.a();
        boolean z = false;
        if (!arrayListA.isEmpty()) {
            g gVar = this.b;
            com.bumptech.glide.h hVarA = gVar.c.a();
            Class<?> cls = gVar.d.getClass();
            Class cls2 = gVar.g;
            Class cls3 = gVar.k;
            androidx.work.impl.model.l lVar = hVarA.h;
            com.bumptech.glide.util.k kVar = (com.bumptech.glide.util.k) ((AtomicReference) lVar.b).getAndSet(null);
            if (kVar == null) {
                kVar = new com.bumptech.glide.util.k(cls, cls2, cls3);
            } else {
                kVar.a = cls;
                kVar.b = cls2;
                kVar.c = cls3;
            }
            synchronized (((C0208f) lVar.c)) {
                list = (List) ((C0208f) lVar.c).get(kVar);
            }
            ((AtomicReference) lVar.b).set(kVar);
            List list2 = list;
            if (list == null) {
                ArrayList arrayList = new ArrayList();
                com.bumptech.glide.load.model.u uVar = hVarA.a;
                synchronized (uVar) {
                    arrayListD = uVar.a.d(cls);
                }
                Iterator it2 = arrayListD.iterator();
                while (it2.hasNext()) {
                    Iterator it3 = hVarA.c.f((Class) it2.next(), cls2).iterator();
                    while (it3.hasNext()) {
                        Class cls4 = (Class) it3.next();
                        if (!hVarA.f.e(cls4, cls3).isEmpty() && !arrayList.contains(cls4)) {
                            arrayList.add(cls4);
                        }
                    }
                }
                androidx.work.impl.model.l lVar2 = hVarA.h;
                List listUnmodifiableList = Collections.unmodifiableList(arrayList);
                synchronized (((C0208f) lVar2.c)) {
                    ((C0208f) lVar2.c).put(new com.bumptech.glide.util.k(cls, cls2, cls3), listUnmodifiableList);
                }
                list2 = arrayList;
            }
            if (!list2.isEmpty()) {
                while (true) {
                    List list3 = this.f;
                    if (list3 != null && this.g < list3.size()) {
                        this.h = null;
                        while (!z && this.g < this.f.size()) {
                            List list4 = this.f;
                            int i = this.g;
                            this.g = i + 1;
                            com.bumptech.glide.load.model.r rVar = (com.bumptech.glide.load.model.r) list4.get(i);
                            File file = this.i;
                            g gVar2 = this.b;
                            this.h = rVar.b(file, gVar2.e, gVar2.f, gVar2.i);
                            if (this.h != null && this.b.c(this.h.c.getDataClass()) != null) {
                                this.h.c.h(this.b.o, this);
                                z = true;
                            }
                        }
                        return z;
                    }
                    int i2 = this.d + 1;
                    this.d = i2;
                    if (i2 >= list2.size()) {
                        int i3 = this.c + 1;
                        this.c = i3;
                        if (i3 >= arrayListA.size()) {
                            break;
                        }
                        this.d = 0;
                    }
                    com.bumptech.glide.load.e eVar = (com.bumptech.glide.load.e) arrayListA.get(this.c);
                    Class cls5 = (Class) list2.get(this.d);
                    com.bumptech.glide.load.l lVarE = this.b.e(cls5);
                    g gVar3 = this.b;
                    this.j = new x(gVar3.c.a, eVar, gVar3.n, gVar3.e, gVar3.f, lVarE, cls5, gVar3.i);
                    File fileC = gVar3.h.a().c(this.j);
                    this.i = fileC;
                    if (fileC != null) {
                        this.e = eVar;
                        this.f = this.b.c.a().f(fileC);
                        this.g = 0;
                    }
                }
            } else if (!File.class.equals(this.b.k)) {
                throw new IllegalStateException("Failed to find any load path from " + this.b.d.getClass() + " to " + this.b.k);
            }
        }
        return false;
    }

    @Override // com.bumptech.glide.load.engine.f
    public final void cancel() {
        com.bumptech.glide.load.model.q qVar = this.h;
        if (qVar != null) {
            qVar.c.cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.d
    public final void i(Object obj) {
        this.a.a(this.e, obj, this.h.c, 4, this.j);
    }
}
