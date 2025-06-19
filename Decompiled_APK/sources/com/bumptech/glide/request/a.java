package com.bumptech.glide.request;

import android.graphics.Bitmap;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import com.bumptech.glide.load.engine.j;
import com.bumptech.glide.load.l;
import com.bumptech.glide.load.resource.bitmap.AbstractC1542e;
import com.bumptech.glide.load.resource.bitmap.r;
import com.bumptech.glide.util.m;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public abstract class a implements Cloneable {
    public int a;
    public int d;
    public boolean i;
    public boolean m;
    public boolean n;
    public boolean p;
    public j b = j.d;
    public com.bumptech.glide.g c = com.bumptech.glide.g.c;
    public boolean e = true;
    public int f = -1;
    public int g = -1;
    public com.bumptech.glide.load.e h = com.bumptech.glide.signature.a.b;
    public com.bumptech.glide.load.h j = new com.bumptech.glide.load.h();
    public com.bumptech.glide.util.c k = new com.bumptech.glide.util.c(0);
    public Class l = Object.class;
    public boolean o = true;

    public static boolean g(int i, int i2) {
        return (i & i2) != 0;
    }

    public a b(a aVar) {
        if (this.n) {
            return clone().b(aVar);
        }
        int i = aVar.a;
        if (g(aVar.a, 1048576)) {
            this.p = aVar.p;
        }
        if (g(aVar.a, 4)) {
            this.b = aVar.b;
        }
        if (g(aVar.a, 8)) {
            this.c = aVar.c;
        }
        if (g(aVar.a, 16)) {
            this.a &= -33;
        }
        if (g(aVar.a, 32)) {
            this.a &= -17;
        }
        if (g(aVar.a, 64)) {
            this.d = 0;
            this.a &= -129;
        }
        if (g(aVar.a, 128)) {
            this.d = aVar.d;
            this.a &= -65;
        }
        if (g(aVar.a, 256)) {
            this.e = aVar.e;
        }
        if (g(aVar.a, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH)) {
            this.g = aVar.g;
            this.f = aVar.f;
        }
        if (g(aVar.a, 1024)) {
            this.h = aVar.h;
        }
        if (g(aVar.a, 4096)) {
            this.l = aVar.l;
        }
        if (g(aVar.a, 8192)) {
            this.a &= -16385;
        }
        if (g(aVar.a, 16384)) {
            this.a &= -8193;
        }
        if (g(aVar.a, 131072)) {
            this.i = aVar.i;
        }
        if (g(aVar.a, 2048)) {
            this.k.putAll(aVar.k);
            this.o = aVar.o;
        }
        this.a |= aVar.a;
        this.j.b.h(aVar.j.b);
        n();
        return this;
    }

    @Override // 
    /* renamed from: c, reason: merged with bridge method [inline-methods] */
    public a clone() {
        try {
            a aVar = (a) super.clone();
            com.bumptech.glide.load.h hVar = new com.bumptech.glide.load.h();
            aVar.j = hVar;
            hVar.b.h(this.j.b);
            com.bumptech.glide.util.c cVar = new com.bumptech.glide.util.c(0);
            aVar.k = cVar;
            cVar.putAll(this.k);
            aVar.m = false;
            aVar.n = false;
            return aVar;
        } catch (CloneNotSupportedException e) {
            throw new RuntimeException(e);
        }
    }

    public final a d(Class cls) {
        if (this.n) {
            return clone().d(cls);
        }
        this.l = cls;
        this.a |= 4096;
        n();
        return this;
    }

    public final a e(j jVar) {
        if (this.n) {
            return clone().e(jVar);
        }
        this.b = jVar;
        this.a |= 4;
        n();
        return this;
    }

    public boolean equals(Object obj) {
        if (obj instanceof a) {
            return f((a) obj);
        }
        return false;
    }

    public final boolean f(a aVar) {
        aVar.getClass();
        if (Float.compare(1.0f, 1.0f) != 0) {
            return false;
        }
        char[] cArr = m.a;
        return this.d == aVar.d && this.e == aVar.e && this.f == aVar.f && this.g == aVar.g && this.i == aVar.i && this.b.equals(aVar.b) && this.c == aVar.c && this.j.equals(aVar.j) && this.k.equals(aVar.k) && this.l.equals(aVar.l) && this.h.equals(aVar.h);
    }

    public final a h(com.bumptech.glide.load.resource.bitmap.m mVar, AbstractC1542e abstractC1542e) {
        if (this.n) {
            return clone().h(mVar, abstractC1542e);
        }
        o(com.bumptech.glide.load.resource.bitmap.m.g, mVar);
        return r(abstractC1542e, false);
    }

    public int hashCode() {
        char[] cArr = m.a;
        return m.h(m.h(m.h(m.h(m.h(m.h(m.h(m.g(0, m.g(0, m.g(1, m.g(this.i ? 1 : 0, m.g(this.g, m.g(this.f, m.g(this.e ? 1 : 0, m.h(m.g(0, m.h(m.g(this.d, m.h(m.g(0, m.g(Float.floatToIntBits(1.0f), 17)), null)), null)), null)))))))), this.b), this.c), this.j), this.k), this.l), this.h), null);
    }

    public final a i(int i, int i2) {
        if (this.n) {
            return clone().i(i, i2);
        }
        this.g = i;
        this.f = i2;
        this.a |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        n();
        return this;
    }

    public final a k() {
        if (this.n) {
            return clone().k();
        }
        this.d = R.drawable.img_placeholder_textbook;
        this.a = (this.a | 128) & (-65);
        n();
        return this;
    }

    public final a l() {
        com.bumptech.glide.g gVar = com.bumptech.glide.g.d;
        if (this.n) {
            return clone().l();
        }
        this.c = gVar;
        this.a |= 8;
        n();
        return this;
    }

    public final a m(com.bumptech.glide.load.resource.bitmap.m mVar, AbstractC1542e abstractC1542e, boolean z) {
        a aVarS = z ? s(mVar, abstractC1542e) : h(mVar, abstractC1542e);
        aVarS.o = true;
        return aVarS;
    }

    public final void n() {
        if (this.m) {
            throw new IllegalStateException("You cannot modify locked T, consider clone()");
        }
    }

    public final a o(com.bumptech.glide.load.g gVar, Object obj) {
        if (this.n) {
            return clone().o(gVar, obj);
        }
        com.bumptech.glide.util.f.b(gVar);
        this.j.b.put(gVar, obj);
        n();
        return this;
    }

    public final a p(com.bumptech.glide.signature.b bVar) {
        if (this.n) {
            return clone().p(bVar);
        }
        this.h = bVar;
        this.a |= 1024;
        n();
        return this;
    }

    public final a q() {
        if (this.n) {
            return clone().q();
        }
        this.e = false;
        this.a |= 256;
        n();
        return this;
    }

    public final a r(l lVar, boolean z) {
        if (this.n) {
            return clone().r(lVar, z);
        }
        r rVar = new r(lVar, z);
        t(Bitmap.class, lVar, z);
        t(Drawable.class, rVar, z);
        t(BitmapDrawable.class, rVar, z);
        t(com.bumptech.glide.load.resource.gif.b.class, new com.bumptech.glide.load.resource.gif.c(lVar), z);
        n();
        return this;
    }

    public final a s(com.bumptech.glide.load.resource.bitmap.m mVar, AbstractC1542e abstractC1542e) {
        if (this.n) {
            return clone().s(mVar, abstractC1542e);
        }
        o(com.bumptech.glide.load.resource.bitmap.m.g, mVar);
        return r(abstractC1542e, true);
    }

    public final a t(Class cls, l lVar, boolean z) {
        if (this.n) {
            return clone().t(cls, lVar, z);
        }
        com.bumptech.glide.util.f.b(lVar);
        this.k.put(cls, lVar);
        int i = this.a;
        this.a = 67584 | i;
        this.o = false;
        if (z) {
            this.a = i | 198656;
            this.i = true;
        }
        n();
        return this;
    }

    public final a u() {
        if (this.n) {
            return clone().u();
        }
        this.p = true;
        this.a |= 1048576;
        n();
        return this;
    }
}
