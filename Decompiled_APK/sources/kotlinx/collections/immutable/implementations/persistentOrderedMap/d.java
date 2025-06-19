package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import com.google.android.gms.internal.mlkit_vision_camera.C1;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import kotlin.collections.AbstractC4922m;
import kotlin.collections.builders.j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends AbstractC4922m implements kotlinx.collections.immutable.f {
    public c a;
    public Object b;
    public Object c;
    public final kotlinx.collections.immutable.implementations.immutableMap.d d;

    public d(c map) {
        Intrinsics.checkNotNullParameter(map, "map");
        this.a = map;
        this.b = map.b;
        this.c = map.c;
        kotlinx.collections.immutable.implementations.immutableMap.c cVar = map.d;
        cVar.getClass();
        this.d = new kotlinx.collections.immutable.implementations.immutableMap.d(cVar);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set a() {
        return new kotlinx.collections.immutable.implementations.immutableMap.f(this);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Set b() {
        return new j(this);
    }

    @Override // kotlinx.collections.immutable.f
    public final kotlinx.collections.immutable.g build() {
        c cVar = this.a;
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        if (cVar != null) {
            kotlinx.collections.immutable.implementations.immutableMap.c cVar2 = dVar.a;
            return cVar;
        }
        kotlinx.collections.immutable.implementations.immutableMap.c cVar3 = dVar.a;
        c cVar4 = new c(this.b, this.c, dVar.build());
        this.a = cVar4;
        return cVar4;
    }

    @Override // java.util.AbstractMap, java.util.Map
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

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean containsKey(Object obj) {
        return this.d.containsKey(obj);
    }

    @Override // kotlin.collections.AbstractC4922m
    public final int d() {
        return this.d.d();
    }

    @Override // kotlin.collections.AbstractC4922m
    public final Collection e() {
        return new androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.j(this);
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        Map otherMap = (Map) obj;
        if (dVar.d() != otherMap.size()) {
            return false;
        }
        if (otherMap instanceof c) {
            kotlinx.collections.immutable.implementations.immutableMap.j jVar = dVar.c;
            kotlinx.collections.immutable.implementations.immutableMap.c cVar = ((c) obj).d;
            return jVar.g(cVar.b, b.f);
        }
        if (otherMap instanceof d) {
            return dVar.c.g(((d) obj).d.c, b.g);
        }
        if (otherMap instanceof kotlinx.collections.immutable.implementations.immutableMap.c) {
            return dVar.c.g(((kotlinx.collections.immutable.implementations.immutableMap.c) obj).b, b.h);
        }
        if (otherMap instanceof kotlinx.collections.immutable.implementations.immutableMap.d) {
            return dVar.c.g(((kotlinx.collections.immutable.implementations.immutableMap.d) obj).c, b.i);
        }
        Intrinsics.checkNotNullParameter(this, "thisMap");
        Intrinsics.checkNotNullParameter(otherMap, "otherMap");
        if (d() != otherMap.size()) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        if (otherMap.isEmpty()) {
            return true;
        }
        Iterator it2 = otherMap.entrySet().iterator();
        while (it2.hasNext()) {
            if (!C1.a(this, (Map.Entry) it2.next())) {
                return false;
            }
        }
        return true;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object get(Object obj) {
        a aVar = (a) this.d.get(obj);
        if (aVar != null) {
            return aVar.a;
        }
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final int hashCode() {
        Intrinsics.checkNotNullParameter(this, "map");
        return entrySet().hashCode();
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object put(Object obj, Object obj2) {
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        a aVar = (a) dVar.get(obj);
        if (aVar != null) {
            Object obj3 = aVar.a;
            if (obj3 == obj2) {
                return obj2;
            }
            this.a = null;
            dVar.put(obj, new a(obj2, aVar.b, aVar.c));
            return obj3;
        }
        this.a = null;
        boolean zIsEmpty = isEmpty();
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        if (zIsEmpty) {
            this.b = obj;
            this.c = obj;
            dVar.put(obj, new a(obj2, bVar, bVar));
            return null;
        }
        Object obj4 = this.c;
        Object obj5 = dVar.get(obj4);
        Intrinsics.d(obj5);
        a aVar2 = (a) obj5;
        dVar.put(obj4, new a(aVar2.a, aVar2.b, obj));
        dVar.put(obj, new a(obj2, obj4, bVar));
        this.c = obj;
        return null;
    }

    @Override // java.util.AbstractMap, java.util.Map
    public final Object remove(Object obj) {
        kotlinx.collections.immutable.implementations.immutableMap.d dVar = this.d;
        a aVar = (a) dVar.remove(obj);
        if (aVar == null) {
            return null;
        }
        this.a = null;
        kotlinx.collections.immutable.internal.b bVar = kotlinx.collections.immutable.internal.b.a;
        Object obj2 = aVar.c;
        Object obj3 = aVar.b;
        if (obj3 != bVar) {
            Object obj4 = dVar.get(obj3);
            Intrinsics.d(obj4);
            a aVar2 = (a) obj4;
            dVar.put(obj3, new a(aVar2.a, aVar2.b, obj2));
        } else {
            this.b = obj2;
        }
        if (obj2 != bVar) {
            Object obj5 = dVar.get(obj2);
            Intrinsics.d(obj5);
            a aVar3 = (a) obj5;
            dVar.put(obj2, new a(aVar3.a, obj3, aVar3.c));
        } else {
            this.c = obj3;
        }
        return aVar.a;
    }

    @Override // java.util.Map
    public final boolean remove(Object obj, Object obj2) {
        a aVar = (a) this.d.get(obj);
        if (aVar == null || !Intrinsics.b(aVar.a, obj2)) {
            return false;
        }
        remove(obj);
        return true;
    }
}
