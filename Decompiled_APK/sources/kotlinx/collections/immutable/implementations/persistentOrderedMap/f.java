package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class f implements Iterator, kotlin.jvm.internal.markers.a {
    public Object a;
    public final d b;
    public Object c;
    public boolean d;
    public int e;
    public int f;

    public f(Object obj, d builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = obj;
        this.b = builder;
        this.c = kotlinx.collections.immutable.internal.b.a;
        this.e = builder.d.e;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.util.Iterator
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final a next() {
        d dVar = this.b;
        if (dVar.d.e != this.e) {
            throw new ConcurrentModificationException();
        }
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        Object obj = this.a;
        this.c = obj;
        this.d = true;
        this.f++;
        V v = dVar.d.get(obj);
        if (v == 0) {
            throw new ConcurrentModificationException(android.support.v4.media.session.a.s(new StringBuilder("Hash code of a key ("), this.a, ") has changed after it was added to the persistent map."));
        }
        a aVar = (a) v;
        this.a = aVar.c;
        return aVar;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.f < this.b.d.d();
    }

    @Override // java.util.Iterator
    public final void remove() {
        if (!this.d) {
            throw new IllegalStateException();
        }
        Object obj = this.c;
        d dVar = this.b;
        O.c(dVar).remove(obj);
        this.c = null;
        this.d = false;
        this.e = dVar.d.e;
        this.f--;
    }
}
