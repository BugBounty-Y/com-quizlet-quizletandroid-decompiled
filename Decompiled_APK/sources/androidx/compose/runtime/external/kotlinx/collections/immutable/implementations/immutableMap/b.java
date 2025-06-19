package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap;

import java.util.NoSuchElementException;

/* loaded from: classes.dex */
public final class b extends a implements kotlin.jvm.internal.markers.d {
    public final h d;
    public Object e;

    public b(h hVar, Object obj, Object obj2) {
        super(0, obj, obj2);
        this.d = hVar;
        this.e = obj2;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a, java.util.Map.Entry
    public final Object getValue() {
        return this.e;
    }

    @Override // androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.a, java.util.Map.Entry
    public final Object setValue(Object obj) {
        Object obj2 = this.e;
        this.e = obj;
        f fVar = (f) this.d.b;
        e eVar = fVar.e;
        Object obj3 = this.b;
        if (!eVar.containsKey(obj3)) {
            return obj2;
        }
        boolean z = fVar.c;
        if (!z) {
            eVar.put(obj3, obj);
        } else {
            if (!z) {
                throw new NoSuchElementException();
            }
            o oVar = ((o[]) fVar.d)[fVar.b];
            Object obj4 = oVar.b[oVar.d];
            eVar.put(obj3, obj);
            fVar.f(obj4 != null ? obj4.hashCode() : 0, eVar.c, obj4, 0);
        }
        fVar.h = eVar.e;
        return obj2;
    }
}
