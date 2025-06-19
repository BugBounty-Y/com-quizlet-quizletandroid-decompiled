package kotlin.sequences;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes3.dex */
public final class e implements Iterator, kotlin.jvm.internal.markers.a {
    public final Iterator b;
    public Object d;
    public final /* synthetic */ Sequence e;
    public final /* synthetic */ int a = 0;
    public int c = -1;

    public e(f fVar) {
        this.e = fVar;
        this.b = fVar.a.iterator();
    }

    public void a() {
        Object next;
        f fVar;
        do {
            Iterator it2 = this.b;
            if (!it2.hasNext()) {
                this.c = 0;
                return;
            } else {
                next = it2.next();
                fVar = (f) this.e;
            }
        } while (((Boolean) fVar.c.invoke(next)).booleanValue() != fVar.b);
        this.d = next;
        this.c = 1;
    }

    public void b() {
        Iterator it2 = this.b;
        if (it2.hasNext()) {
            Object next = it2.next();
            if (((Boolean) ((t) this.e).c.invoke(next)).booleanValue()) {
                this.c = 1;
                this.d = next;
                return;
            }
        }
        this.c = 0;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.c == -1) {
                    a();
                }
                if (this.c == 1) {
                }
                break;
            default:
                if (this.c == -1) {
                    b();
                }
                if (this.c == 1) {
                }
                break;
        }
        return true;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                if (this.c == -1) {
                    a();
                }
                if (this.c == 0) {
                    throw new NoSuchElementException();
                }
                Object obj = this.d;
                this.d = null;
                this.c = -1;
                return obj;
            default:
                if (this.c == -1) {
                    b();
                }
                if (this.c == 0) {
                    throw new NoSuchElementException();
                }
                Object obj2 = this.d;
                this.d = null;
                this.c = -1;
                return obj2;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public e(t tVar) {
        this.e = tVar;
        this.b = tVar.b.iterator();
    }
}
