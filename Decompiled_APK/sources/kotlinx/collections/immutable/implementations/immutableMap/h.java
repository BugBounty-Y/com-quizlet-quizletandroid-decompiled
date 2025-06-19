package kotlinx.collections.immutable.implementations.immutableMap;

import androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableMap.o;
import java.util.Iterator;
import java.util.Map;
import kotlin.collections.AbstractC4925p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends AbstractC4925p implements kotlinx.collections.immutable.c {
    public final /* synthetic */ int b;
    public final c c;

    public h(c map, int i) {
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
                return this.c.containsKey(obj);
        }
    }

    @Override // kotlin.collections.AbstractC4925p, java.util.Collection, java.lang.Iterable, java.util.Set
    public final Iterator iterator() {
        switch (this.b) {
            case 0:
                j node = this.c.b;
                Intrinsics.checkNotNullParameter(node, "node");
                o[] oVarArr = new o[8];
                for (int i = 0; i < 8; i++) {
                    oVarArr[i] = new k(0);
                }
                return new i(node, oVarArr);
            default:
                j node2 = this.c.b;
                Intrinsics.checkNotNullParameter(node2, "node");
                o[] oVarArr2 = new o[8];
                for (int i2 = 0; i2 < 8; i2++) {
                    oVarArr2[i2] = new k(1);
                }
                return new i(node2, oVarArr2);
        }
    }
}
