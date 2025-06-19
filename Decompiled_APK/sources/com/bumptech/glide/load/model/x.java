package com.bumptech.glide.load.model;

import com.bumptech.glide.Registry$NoModelLoaderAvailableException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class x {
    public static final C1535c e = new C1535c(6);
    public static final B f = new B(2);
    public final ArrayList a;
    public final C1535c b;
    public final HashSet c;
    public final com.quizlet.data.repository.course.membership.c d;

    public x(com.quizlet.data.repository.course.membership.c cVar) {
        C1535c c1535c = e;
        this.a = new ArrayList();
        this.c = new HashSet();
        this.d = cVar;
        this.b = c1535c;
    }

    public final synchronized void a(Class cls, Class cls2, s sVar) {
        w wVar = new w(cls, cls2, sVar);
        ArrayList arrayList = this.a;
        arrayList.add(arrayList.size(), wVar);
    }

    public final synchronized r b(Class cls, Class cls2) {
        try {
            ArrayList arrayList = new ArrayList();
            Iterator it2 = this.a.iterator();
            boolean z = false;
            while (true) {
                boolean z2 = true;
                if (!it2.hasNext()) {
                    break;
                }
                w wVar = (w) it2.next();
                if (this.c.contains(wVar)) {
                    z = true;
                } else {
                    if (!wVar.a.isAssignableFrom(cls) || !wVar.b.isAssignableFrom(cls2)) {
                        z2 = false;
                    }
                    if (z2) {
                        this.c.add(wVar);
                        arrayList.add(wVar.c.a(this));
                        this.c.remove(wVar);
                    }
                }
            }
            if (arrayList.size() > 1) {
                C1535c c1535c = this.b;
                com.quizlet.data.repository.course.membership.c cVar = this.d;
                c1535c.getClass();
                return new C1534b(2, arrayList, cVar);
            }
            if (arrayList.size() == 1) {
                return (r) arrayList.get(0);
            }
            if (z) {
                return f;
            }
            throw new Registry$NoModelLoaderAvailableException("Failed to find any ModelLoaders for model: " + cls + " and data: " + cls2);
        } catch (Throwable th) {
            this.c.clear();
            throw th;
        }
    }

    public final synchronized ArrayList c(Class cls) {
        ArrayList arrayList;
        try {
            arrayList = new ArrayList();
            Iterator it2 = this.a.iterator();
            while (it2.hasNext()) {
                w wVar = (w) it2.next();
                if (!this.c.contains(wVar) && wVar.a.isAssignableFrom(cls)) {
                    this.c.add(wVar);
                    arrayList.add(wVar.c.a(this));
                    this.c.remove(wVar);
                }
            }
        } finally {
        }
        return arrayList;
    }

    public final synchronized ArrayList d(Class cls) {
        ArrayList arrayList;
        arrayList = new ArrayList();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            w wVar = (w) it2.next();
            if (!arrayList.contains(wVar.b) && wVar.a.isAssignableFrom(cls)) {
                arrayList.add(wVar.b);
            }
        }
        return arrayList;
    }

    public final synchronized ArrayList e() {
        ArrayList arrayList;
        arrayList = new ArrayList();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            w wVar = (w) it2.next();
            if (wVar.a.isAssignableFrom(h.class) && wVar.b.isAssignableFrom(InputStream.class)) {
                it2.remove();
                arrayList.add(wVar.c);
            }
        }
        return arrayList;
    }
}
