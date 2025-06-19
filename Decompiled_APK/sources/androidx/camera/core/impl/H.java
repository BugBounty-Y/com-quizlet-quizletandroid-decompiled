package androidx.camera.core.impl;

import androidx.camera.camera2.internal.C0143u;
import java.util.Iterator;
import java.util.Objects;
import java.util.Set;

/* loaded from: classes.dex */
public interface H {
    static void t(X x, H h, H h2, C0162c c0162c) {
        if (!Objects.equals(c0162c, P.l0)) {
            x.l(c0162c, h2.i(c0162c), h2.e(c0162c));
            return;
        }
        androidx.camera.core.resolutionselector.b bVar = (androidx.camera.core.resolutionselector.b) h2.j(c0162c, null);
        androidx.camera.core.resolutionselector.b bVar2 = (androidx.camera.core.resolutionselector.b) h.j(c0162c, null);
        G gI = h2.i(c0162c);
        if (bVar == null) {
            bVar = bVar2;
        } else if (bVar2 != null) {
            androidx.camera.core.resolutionselector.a aVar = bVar.a;
            if (aVar == null) {
                aVar = bVar2.a;
            }
            androidx.camera.core.resolutionselector.c cVar = bVar.b;
            if (cVar == null) {
                cVar = bVar2.b;
            }
            bVar2 = new androidx.camera.core.resolutionselector.b(aVar, cVar);
            bVar = bVar2;
        }
        x.l(c0162c, gI, bVar);
    }

    static C0163c0 z(H h, H h2) {
        if (h == null && h2 == null) {
            return C0163c0.c;
        }
        X xK = h2 != null ? X.k(h2) : X.b();
        if (h != null) {
            Iterator it2 = h.f().iterator();
            while (it2.hasNext()) {
                t(xK, h2, h, (C0162c) it2.next());
            }
        }
        return C0163c0.a(xK);
    }

    boolean c(C0162c c0162c);

    Object d(C0162c c0162c, G g);

    Object e(C0162c c0162c);

    Set f();

    Set g(C0162c c0162c);

    void h(C0143u c0143u);

    G i(C0162c c0162c);

    Object j(C0162c c0162c, Object obj);
}
