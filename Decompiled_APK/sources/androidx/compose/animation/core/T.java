package androidx.compose.animation.core;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;

/* loaded from: classes.dex */
public final class T extends J0 {
    public final InterfaceC0773a0 c;
    public final InterfaceC0773a0 d;

    public T(Object obj) {
        super(0);
        this.c = C0776c.z(obj);
        this.d = C0776c.z(obj);
    }

    @Override // androidx.compose.animation.core.J0
    public final Object I() {
        return ((androidx.compose.runtime.L0) this.d).getValue();
    }

    @Override // androidx.compose.animation.core.J0
    public final void L(Object obj) {
        ((androidx.compose.runtime.L0) this.c).setValue(obj);
    }

    @Override // androidx.compose.animation.core.J0
    public final void M(E0 e0) {
    }

    @Override // androidx.compose.animation.core.J0
    public final void N() {
    }

    @Override // androidx.compose.animation.core.J0
    public final Object t() {
        return ((androidx.compose.runtime.L0) this.c).getValue();
    }
}
