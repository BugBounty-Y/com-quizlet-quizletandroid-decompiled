package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.persistentOrderedSet;

import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class c implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a;
    public Object b;
    public final Map c;
    public int d;

    public c(Object obj, Map hashMap, int i) {
        this.a = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(hashMap, "hashMap");
                this.b = obj;
                this.c = hashMap;
                break;
            case 2:
                Intrinsics.checkNotNullParameter(hashMap, "map");
                this.b = obj;
                this.c = hashMap;
                break;
            default:
                this.b = obj;
                this.c = hashMap;
                break;
        }
    }

    public kotlinx.collections.immutable.implementations.persistentOrderedMap.a a() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        Object obj = this.c.get(this.b);
        if (obj == null) {
            throw new ConcurrentModificationException(android.support.v4.media.session.a.s(new StringBuilder("Hash code of a key ("), this.b, ") has changed after it was added to the persistent map."));
        }
        kotlinx.collections.immutable.implementations.persistentOrderedMap.a aVar = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) obj;
        this.d++;
        this.b = aVar.c;
        return aVar;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.d < this.c.size()) {
                }
                break;
            case 1:
                if (this.d < this.c.size()) {
                }
                break;
            default:
                if (this.d < this.c.size()) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public Object next() {
        switch (this.a) {
            case 0:
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                Object obj = this.b;
                this.d++;
                Object obj2 = this.c.get(obj);
                if (obj2 != null) {
                    this.b = ((a) obj2).b;
                    return obj;
                }
                throw new ConcurrentModificationException("Hash code of an element (" + obj + ") has changed after it was added to the persistent set.");
            case 1:
                return a();
            default:
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                Object obj3 = this.b;
                this.d++;
                Object obj4 = this.c.get(obj3);
                if (obj4 != null) {
                    this.b = ((kotlinx.collections.immutable.implementations.persistentOrderedSet.a) obj4).b;
                    return obj3;
                }
                throw new ConcurrentModificationException("Hash code of an element (" + obj3 + ") has changed after it was added to the persistent set.");
        }
    }

    @Override // java.util.Iterator
    public void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            case 1:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }
}
