package androidx.camera.camera2.internal;

import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import java.util.UUID;

/* loaded from: classes.dex */
public final class b0 implements A0 {
    public final androidx.camera.core.impl.X a;

    public b0() {
        androidx.camera.core.impl.X xB = androidx.camera.core.impl.X.b();
        xB.m(A0.p0, new J());
        xB.m(androidx.camera.core.impl.O.b0, 34);
        xB.m(androidx.camera.core.internal.k.A0, c0.class);
        xB.m(androidx.camera.core.internal.k.z0, c0.class.getCanonicalName() + "-" + UUID.randomUUID());
        this.a = xB;
    }

    @Override // androidx.camera.core.impl.j0
    public final androidx.camera.core.impl.H n() {
        return this.a;
    }

    @Override // androidx.camera.core.impl.A0
    public final C0 x() {
        return C0.f;
    }
}
