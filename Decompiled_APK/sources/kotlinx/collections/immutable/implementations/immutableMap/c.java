package kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.m;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import kotlin.collections.AbstractC4919j;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC4919j implements kotlinx.collections.immutable.g {
    public static final c d = new c(j.e, 0);
    public final j b;
    public final int c;

    public c(j node, int i) {
        Intrinsics.checkNotNullParameter(node, "node");
        this.b = node;
        this.c = i;
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set a() {
        return new h(this, 0);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Set b() {
        return new h(this, 1);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final boolean containsKey(Object obj) {
        return this.b.d(obj != null ? obj.hashCode() : 0, 0, obj);
    }

    @Override // kotlin.collections.AbstractC4919j
    public final int d() {
        return this.c;
    }

    @Override // kotlin.collections.AbstractC4919j
    public final Collection e() {
        return new m(this);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        Map map = (Map) obj;
        if (d() != map.size()) {
            return false;
        }
        boolean z = map instanceof kotlinx.collections.immutable.implementations.persistentOrderedMap.c;
        j jVar = this.b;
        return z ? jVar.g(((kotlinx.collections.immutable.implementations.persistentOrderedMap.c) obj).d.b, b.b) : map instanceof kotlinx.collections.immutable.implementations.persistentOrderedMap.d ? jVar.g(((kotlinx.collections.immutable.implementations.persistentOrderedMap.d) obj).d.c, b.c) : map instanceof c ? jVar.g(((c) obj).b, b.d) : map instanceof d ? jVar.g(((d) obj).c, b.e) : super.equals(obj);
    }

    @Override // kotlin.collections.AbstractC4919j, java.util.Map
    public final Object get(Object obj) {
        return this.b.h(obj != null ? obj.hashCode() : 0, 0, obj);
    }
}
