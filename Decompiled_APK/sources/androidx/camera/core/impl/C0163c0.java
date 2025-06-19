package androidx.camera.core.impl;

import android.util.ArrayMap;
import androidx.camera.camera2.internal.C0143u;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/* renamed from: androidx.camera.core.impl.c0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public class C0163c0 implements H {
    public static final androidx.camera.camera2.internal.a0 b;
    public static final C0163c0 c;
    public final TreeMap a;

    static {
        androidx.camera.camera2.internal.a0 a0Var = new androidx.camera.camera2.internal.a0(1);
        b = a0Var;
        c = new C0163c0(new TreeMap(a0Var));
    }

    public C0163c0(TreeMap treeMap) {
        this.a = treeMap;
    }

    public static C0163c0 a(H h) {
        if (C0163c0.class.equals(h.getClass())) {
            return (C0163c0) h;
        }
        TreeMap treeMap = new TreeMap(b);
        for (C0162c c0162c : h.f()) {
            Set<G> setG = h.g(c0162c);
            ArrayMap arrayMap = new ArrayMap();
            for (G g : setG) {
                arrayMap.put(g, h.d(c0162c, g));
            }
            treeMap.put(c0162c, arrayMap);
        }
        return new C0163c0(treeMap);
    }

    @Override // androidx.camera.core.impl.H
    public final boolean c(C0162c c0162c) {
        return this.a.containsKey(c0162c);
    }

    @Override // androidx.camera.core.impl.H
    public final Object d(C0162c c0162c, G g) {
        Map map = (Map) this.a.get(c0162c);
        if (map == null) {
            throw new IllegalArgumentException("Option does not exist: " + c0162c);
        }
        if (map.containsKey(g)) {
            return map.get(g);
        }
        throw new IllegalArgumentException("Option does not exist: " + c0162c + " with priority=" + g);
    }

    @Override // androidx.camera.core.impl.H
    public final Object e(C0162c c0162c) {
        Map map = (Map) this.a.get(c0162c);
        if (map != null) {
            return map.get((G) Collections.min(map.keySet()));
        }
        throw new IllegalArgumentException("Option does not exist: " + c0162c);
    }

    @Override // androidx.camera.core.impl.H
    public final Set f() {
        return Collections.unmodifiableSet(this.a.keySet());
    }

    @Override // androidx.camera.core.impl.H
    public final Set g(C0162c c0162c) {
        Map map = (Map) this.a.get(c0162c);
        return map == null ? Collections.EMPTY_SET : Collections.unmodifiableSet(map.keySet());
    }

    @Override // androidx.camera.core.impl.H
    public final void h(C0143u c0143u) {
        for (Map.Entry entry : this.a.tailMap(new C0162c("camera2.captureRequest.option.", Void.class, null)).entrySet()) {
            if (!((C0162c) entry.getKey()).a.startsWith("camera2.captureRequest.option.")) {
                return;
            }
            C0162c c0162c = (C0162c) entry.getKey();
            com.google.firebase.platforminfo.c cVar = (com.google.firebase.platforminfo.c) c0143u.b;
            H h = (H) c0143u.c;
            ((X) cVar.a).l(c0162c, h.i(c0162c), h.e(c0162c));
        }
    }

    @Override // androidx.camera.core.impl.H
    public final G i(C0162c c0162c) {
        Map map = (Map) this.a.get(c0162c);
        if (map != null) {
            return (G) Collections.min(map.keySet());
        }
        throw new IllegalArgumentException("Option does not exist: " + c0162c);
    }

    @Override // androidx.camera.core.impl.H
    public final Object j(C0162c c0162c, Object obj) {
        try {
            return e(c0162c);
        } catch (IllegalArgumentException unused) {
            return obj;
        }
    }
}
