package androidx.camera.core.streamsharing;

import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.H;
import androidx.camera.core.impl.P;
import androidx.camera.core.internal.l;
import java.util.List;

/* loaded from: classes.dex */
public final class e implements A0, P, l {
    public static final C0162c b = new C0162c("camerax.core.streamSharing.captureTypes", List.class, null);
    public final C0163c0 a;

    public e(C0163c0 c0163c0) {
        this.a = c0163c0;
    }

    @Override // androidx.camera.core.impl.j0
    public final H n() {
        return this.a;
    }
}
