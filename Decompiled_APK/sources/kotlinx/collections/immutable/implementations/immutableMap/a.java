package kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o;
import java.util.Map;
import java.util.NoSuchElementException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a implements kotlin.jvm.internal.markers.d {
    public final /* synthetic */ int d = 0;
    public final Object e;
    public Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h parentIterator, Object obj, Object obj2) {
        super(1, obj, obj2);
        Intrinsics.checkNotNullParameter(parentIterator, "parentIterator");
        this.e = parentIterator;
        this.f = obj2;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a, java.util.Map.Entry
    public final Object getValue() {
        switch (this.d) {
            case 0:
                return this.f;
            default:
                return ((kotlinx.collections.immutable.implementations.persistentOrderedMap.a) this.f).a;
        }
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a, java.util.Map.Entry
    public final Object setValue(Object obj) {
        switch (this.d) {
            case 0:
                Object obj2 = this.f;
                this.f = obj;
                e eVar = (e) ((androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.h) this.e).b;
                d dVar = eVar.e;
                Object obj3 = this.b;
                if (dVar.containsKey(obj3)) {
                    boolean z = eVar.c;
                    if (!z) {
                        dVar.put(obj3, obj);
                    } else {
                        if (!z) {
                            throw new NoSuchElementException();
                        }
                        o oVar = ((o[]) eVar.d)[eVar.b];
                        Object obj4 = oVar.b[oVar.d];
                        dVar.put(obj3, obj);
                        eVar.f(obj4 != null ? obj4.hashCode() : 0, dVar.c, obj4, 0, 0, false);
                    }
                    eVar.h = dVar.e;
                }
                return obj2;
            default:
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a aVar = (kotlinx.collections.immutable.implementations.persistentOrderedMap.a) this.f;
                kotlinx.collections.immutable.implementations.persistentOrderedMap.a aVar2 = new kotlinx.collections.immutable.implementations.persistentOrderedMap.a(obj, aVar.b, aVar.c);
                this.f = aVar2;
                ((Map) this.e).put(this.b, aVar2);
                return aVar.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Map mutableMap, Object obj, kotlinx.collections.immutable.implementations.persistentOrderedMap.a links) {
        super(1, obj, links.a);
        Intrinsics.checkNotNullParameter(mutableMap, "mutableMap");
        Intrinsics.checkNotNullParameter(links, "links");
        this.e = mutableMap;
        this.f = links;
    }
}
