package androidx.camera.core;

import android.util.Size;
import android.view.Surface;

/* loaded from: classes.dex */
public final class g0 extends androidx.camera.core.impl.J {
    public final /* synthetic */ int o = 1;
    public final Object p;

    public g0(Surface surface, Size size, int i) {
        super(size, i);
        this.p = surface;
    }

    @Override // androidx.camera.core.impl.J
    public final com.google.common.util.concurrent.e f() {
        switch (this.o) {
            case 0:
                return ((j0) this.p).f;
            default:
                return androidx.camera.core.impl.utils.futures.i.c((Surface) this.p);
        }
    }

    public g0(Surface surface) {
        super(androidx.camera.core.impl.J.k, 0);
        this.p = surface;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g0(j0 j0Var, Size size) {
        super(size, 34);
        this.p = j0Var;
    }
}
