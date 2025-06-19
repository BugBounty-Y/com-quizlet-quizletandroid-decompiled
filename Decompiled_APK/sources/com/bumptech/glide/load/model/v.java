package com.bumptech.glide.load.model;

import com.bumptech.glide.load.engine.GlideException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes.dex */
public final class v implements com.bumptech.glide.load.data.e, com.bumptech.glide.load.data.d {
    public final ArrayList a;
    public final com.quizlet.data.repository.course.membership.c b;
    public int c;
    public com.bumptech.glide.g d;
    public com.bumptech.glide.load.data.d e;
    public List f;
    public boolean g;

    public v(ArrayList arrayList, com.quizlet.data.repository.course.membership.c cVar) {
        this.b = cVar;
        if (arrayList.isEmpty()) {
            throw new IllegalArgumentException("Must not be empty.");
        }
        this.a = arrayList;
        this.c = 0;
    }

    @Override // com.bumptech.glide.load.data.d
    public final void a(Exception exc) {
        List list = this.f;
        com.bumptech.glide.util.f.c(list, "Argument must not be null");
        list.add(exc);
        b();
    }

    public final void b() {
        if (this.g) {
            return;
        }
        if (this.c < this.a.size() - 1) {
            this.c++;
            h(this.d, this.e);
        } else {
            com.bumptech.glide.util.f.b(this.f);
            this.e.a(new GlideException("Fetch failed", new ArrayList(this.f)));
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        this.g = true;
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((com.bumptech.glide.load.data.e) it2.next()).cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() {
        List list = this.f;
        if (list != null) {
            this.b.o(list);
        }
        this.f = null;
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((com.bumptech.glide.load.data.e) it2.next()).f();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        return ((com.bumptech.glide.load.data.e) this.a.get(0)).g();
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        return ((com.bumptech.glide.load.data.e) this.a.get(0)).getDataClass();
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) {
        this.d = gVar;
        this.e = dVar;
        this.f = (List) this.b.a();
        ((com.bumptech.glide.load.data.e) this.a.get(this.c)).h(gVar, this);
        if (this.g) {
            cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.d
    public final void i(Object obj) {
        if (obj != null) {
            this.e.i(obj);
        } else {
            b();
        }
    }
}
