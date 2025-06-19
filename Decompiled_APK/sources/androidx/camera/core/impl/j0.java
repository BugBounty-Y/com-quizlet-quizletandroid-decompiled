package androidx.camera.core.impl;

import androidx.camera.camera2.internal.C0143u;
import java.util.Set;

/* loaded from: classes.dex */
public interface j0 extends H {
    @Override // androidx.camera.core.impl.H
    default boolean c(C0162c c0162c) {
        return n().c(c0162c);
    }

    @Override // androidx.camera.core.impl.H
    default Object d(C0162c c0162c, G g) {
        return n().d(c0162c, g);
    }

    @Override // androidx.camera.core.impl.H
    default Object e(C0162c c0162c) {
        return n().e(c0162c);
    }

    @Override // androidx.camera.core.impl.H
    default Set f() {
        return n().f();
    }

    @Override // androidx.camera.core.impl.H
    default Set g(C0162c c0162c) {
        return n().g(c0162c);
    }

    @Override // androidx.camera.core.impl.H
    default void h(C0143u c0143u) {
        n().h(c0143u);
    }

    @Override // androidx.camera.core.impl.H
    default G i(C0162c c0162c) {
        return n().i(c0162c);
    }

    @Override // androidx.camera.core.impl.H
    default Object j(C0162c c0162c, Object obj) {
        return n().j(c0162c, obj);
    }

    H n();
}
