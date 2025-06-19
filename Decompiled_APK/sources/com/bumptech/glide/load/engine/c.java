package com.bumptech.glide.load.engine;

import java.io.File;
import java.util.List;

/* loaded from: classes.dex */
public final class c implements f, com.bumptech.glide.load.data.d {
    public final List a;
    public final g b;
    public final e c;
    public int d = -1;
    public com.bumptech.glide.load.e e;
    public List f;
    public int g;
    public volatile com.bumptech.glide.load.model.q h;
    public File i;

    public c(List list, g gVar, e eVar) {
        this.a = list;
        this.b = gVar;
        this.c = eVar;
    }

    @Override // com.bumptech.glide.load.data.d
    public final void a(Exception exc) {
        this.c.c(this.e, exc, this.h.c, 3);
    }

    @Override // com.bumptech.glide.load.engine.f
    public final boolean b() {
        while (true) {
            List list = this.f;
            boolean z = false;
            if (list != null && this.g < list.size()) {
                this.h = null;
                while (!z && this.g < this.f.size()) {
                    List list2 = this.f;
                    int i = this.g;
                    this.g = i + 1;
                    com.bumptech.glide.load.model.r rVar = (com.bumptech.glide.load.model.r) list2.get(i);
                    File file = this.i;
                    g gVar = this.b;
                    this.h = rVar.b(file, gVar.e, gVar.f, gVar.i);
                    if (this.h != null && this.b.c(this.h.c.getDataClass()) != null) {
                        this.h.c.h(this.b.o, this);
                        z = true;
                    }
                }
                return z;
            }
            int i2 = this.d + 1;
            this.d = i2;
            if (i2 >= this.a.size()) {
                return false;
            }
            com.bumptech.glide.load.e eVar = (com.bumptech.glide.load.e) this.a.get(this.d);
            g gVar2 = this.b;
            File fileC = gVar2.h.a().c(new d(eVar, gVar2.n));
            this.i = fileC;
            if (fileC != null) {
                this.e = eVar;
                this.f = this.b.c.a().f(fileC);
                this.g = 0;
            }
        }
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
        this.c.a(this.e, obj, this.h.c, 3, this.e);
    }
}
