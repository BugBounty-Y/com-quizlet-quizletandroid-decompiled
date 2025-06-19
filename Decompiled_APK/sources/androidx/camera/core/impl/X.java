package androidx.camera.core.impl;

import android.util.ArrayMap;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

/* loaded from: classes.dex */
public final class X extends C0163c0 implements W {
    public static X b() {
        return new X(new TreeMap(C0163c0.b));
    }

    public static X k(H h) {
        TreeMap treeMap = new TreeMap(C0163c0.b);
        for (C0162c c0162c : h.f()) {
            Set<G> setG = h.g(c0162c);
            ArrayMap arrayMap = new ArrayMap();
            for (G g : setG) {
                arrayMap.put(g, h.d(c0162c, g));
            }
            treeMap.put(c0162c, arrayMap);
        }
        return new X(treeMap);
    }

    public final void l(C0162c c0162c, G g, Object obj) {
        G g2;
        TreeMap treeMap = this.a;
        Map map = (Map) treeMap.get(c0162c);
        if (map == null) {
            ArrayMap arrayMap = new ArrayMap();
            treeMap.put(c0162c, arrayMap);
            arrayMap.put(g, obj);
            return;
        }
        G g3 = (G) Collections.min(map.keySet());
        if (Objects.equals(map.get(g3), obj) || g3 != (g2 = G.b) || g != g2) {
            map.put(g, obj);
            return;
        }
        throw new IllegalArgumentException("Option values conflicts: " + c0162c.a + ", existing value (" + g3 + ")=" + map.get(g3) + ", conflicting (" + g + ")=" + obj);
    }

    public final void m(C0162c c0162c, Object obj) {
        l(c0162c, G.c, obj);
    }
}
