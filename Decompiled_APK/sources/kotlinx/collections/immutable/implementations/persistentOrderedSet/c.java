package kotlinx.collections.immutable.implementations.persistentOrderedSet;

import com.quizlet.ui.compose.C4830x;
import java.util.Iterator;
import java.util.Set;
import kotlin.collections.AbstractC4923n;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.collections.immutable.h;

/* loaded from: classes3.dex */
public final class c extends AbstractC4923n implements h {
    public b a;
    public Object b;
    public Object c;
    public final kotlinx.collections.immutable.implementations.immutableMap.d d;

    public c(b set) {
        Intrinsics.checkNotNullParameter(set, "set");
        this.a = set;
        this.b = set.b;
        this.c = set.c;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = set.d;
        cVar.getClass();
        this.d = new kotlinx.collections.immutable.implementations.immutableMap.d(cVar);
    }

    @Override // kotlin.collections.AbstractC4923n
    public final int a() {
        return this.d.d();
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean add(Object obj) {
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        if (dVar.containsKey(obj)) {
            return false;
        }
        this.a = null;
        boolean zIsEmpty = isEmpty();
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        if (zIsEmpty) {
            this.b = obj;
            this.c = obj;
            dVar.put(obj, new a(bVar, bVar));
            return true;
        }
        Object obj2 = dVar.get(this.c);
        Intrinsics.d(obj2);
        dVar.put(this.c, new a(((a) obj2).a, obj));
        dVar.put(obj, new a(this.c, bVar));
        this.c = obj;
        return true;
    }

    public final b b() {
        b bVar = this.a;
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        if (bVar != null) {
            kotlinx.collections.immutable.implementations.immutableMap.c cVar = dVar.a;
            return bVar;
        }
        kotlinx.collections.immutable.implementations.immutableMap.c cVar2 = dVar.a;
        b bVar2 = new b(this.b, this.c, dVar.build());
        this.a = bVar2;
        return bVar2;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final void clear() {
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        if (!dVar.isEmpty()) {
            this.a = null;
        }
        dVar.clear();
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        this.b = bVar;
        this.c = bVar;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        return this.d.containsKey(obj);
    }

    @Override // java.util.AbstractSet, java.util.Collection, java.util.Set
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Set)) {
            return false;
        }
        Set set = (Set) obj;
        if (a() != set.size()) {
            return false;
        }
        boolean z = set instanceof b;
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        return z ? dVar.c.g(((b) obj).d.b, new C4830x(13, (byte) 0)) : set instanceof c ? dVar.c.g(((c) obj).d.c, new C4830x(14, (byte) 0)) : super.equals(obj);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        return new d(this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean remove(Object obj) {
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        a aVar = (a) dVar.remove(obj);
        if (aVar == null) {
            return false;
        }
        this.a = null;
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        Object obj2 = aVar.b;
        Object obj3 = aVar.a;
        if (obj3 != bVar) {
            Object obj4 = dVar.get(obj3);
            Intrinsics.d(obj4);
            dVar.put(obj3, new a(((a) obj4).a, obj2));
        } else {
            this.b = obj2;
        }
        if (obj2 == bVar) {
            this.c = obj3;
            return true;
        }
        Object obj5 = dVar.get(obj2);
        Intrinsics.d(obj5);
        dVar.put(obj2, new a(obj3, ((a) obj5).b));
        return true;
    }
}
