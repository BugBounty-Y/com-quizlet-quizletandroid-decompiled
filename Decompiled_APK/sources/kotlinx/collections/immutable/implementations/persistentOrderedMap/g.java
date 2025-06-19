package kotlinx.collections.immutable.implementations.persistentOrderedMap;

import java.util.Iterator;
import java.util.Map;
import kotlin.collections.AbstractC4925p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends AbstractC4925p implements kotlinx.collections.immutable.c {
    public final /* synthetic */ int b;
    public final c c;

    public g(c map, int i) {
        this.b = i;
        switch (i) {
            case 1:
                Intrinsics.checkNotNullParameter(map, "map");
                this.c = map;
                break;
            default:
                Intrinsics.checkNotNullParameter(map, "map");
                this.c = map;
                break;
        }
    }

    @Override // kotlin.collections.AbstractC4911b
    public final int a() {
        switch (this.b) {
        }
        return this.c.d();
    }

    @Override // kotlin.collections.AbstractC4911b, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        switch (this.b) {
            case 0:
                if (!(obj instanceof Map.Entry)) {
                    return false;
                }
                Map.Entry element = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(element, "element");
                c map = this.c;
                Intrinsics.checkNotNullParameter(map, "map");
                Intrinsics.checkNotNullParameter(element, "element");
                Object obj2 = map.get(element.getKey());
                return obj2 != null ? obj2.equals(element.getValue()) : element.getValue() == null && map.containsKey(element.getKey());
            default:
                return this.c.d.containsKey(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                return new h(this.c, 0);
            default:
                return new h(this.c, 1);
        }
    }
}
