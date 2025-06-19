package com.bumptech.glide.load.engine.bitmap_recycle;

/* loaded from: classes.dex */
public final class d implements g {
    public final e a;
    public int b;
    public Class c;

    public d(e eVar) {
        this.a = eVar;
    }

    @Override // com.bumptech.glide.load.engine.bitmap_recycle.g
    public final void a() {
        this.a.J(this);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof d) {
            d dVar = (d) obj;
            if (this.b == dVar.b && this.c == dVar.c) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        int i = this.b * 31;
        Class cls = this.c;
        return i + (cls != null ? cls.hashCode() : 0);
    }

    public final String toString() {
        return "Key{size=" + this.b + "array=" + this.c + '}';
    }
}
