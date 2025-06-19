package androidx.datastore.preferences.protobuf;

import java.util.AbstractMap;
import java.util.Iterator;
import java.util.Map;

/* loaded from: classes.dex */
public final class Y implements Iterator {
    public final /* synthetic */ int a;
    public int b = -1;
    public boolean c;
    public Iterator d;
    public final /* synthetic */ AbstractMap e;

    public /* synthetic */ Y(AbstractMap abstractMap, int i) {
        this.a = i;
        this.e = abstractMap;
    }

    public final Iterator a() {
        switch (this.a) {
            case 0:
                if (this.d == null) {
                    this.d = ((W) this.e).b.entrySet().iterator();
                }
                break;
            default:
                if (this.d == null) {
                    this.d = ((com.google.protobuf.e0) this.e).c.entrySet().iterator();
                }
                break;
        }
        return this.d;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                int i = this.b + 1;
                W w = (W) this.e;
                if (i >= w.a.size()) {
                    if (w.b.isEmpty() || !a().hasNext()) {
                    }
                }
                break;
            default:
                int i2 = this.b + 1;
                com.google.protobuf.e0 e0Var = (com.google.protobuf.e0) this.e;
                if (i2 >= e0Var.b.size()) {
                    if (e0Var.c.isEmpty() || !a().hasNext()) {
                    }
                }
                break;
        }
        return true;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                this.c = true;
                int i = this.b + 1;
                this.b = i;
                W w = (W) this.e;
                if (i >= w.a.size()) {
                    break;
                } else {
                    break;
                }
            default:
                this.c = true;
                int i2 = this.b + 1;
                this.b = i2;
                com.google.protobuf.e0 e0Var = (com.google.protobuf.e0) this.e;
                if (i2 >= e0Var.b.size()) {
                    break;
                } else {
                    break;
                }
        }
        return (Map.Entry) a().next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        AbstractMap abstractMap = this.e;
        switch (this.a) {
            case 0:
                if (!this.c) {
                    throw new IllegalStateException("remove() was called before next()");
                }
                this.c = false;
                int i = W.f;
                W w = (W) abstractMap;
                w.b();
                if (this.b >= w.a.size()) {
                    a().remove();
                    return;
                }
                int i2 = this.b;
                this.b = i2 - 1;
                w.i(i2);
                return;
            default:
                if (!this.c) {
                    throw new IllegalStateException("remove() was called before next()");
                }
                this.c = false;
                int i3 = com.google.protobuf.e0.g;
                com.google.protobuf.e0 e0Var = (com.google.protobuf.e0) abstractMap;
                e0Var.b();
                if (this.b >= e0Var.b.size()) {
                    a().remove();
                    return;
                }
                int i4 = this.b;
                this.b = i4 - 1;
                e0Var.h(i4);
                return;
        }
    }
}
