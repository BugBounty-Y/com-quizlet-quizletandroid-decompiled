package androidx.work;

import java.util.Set;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K extends androidx.camera.view.j {
    @Override // androidx.camera.view.j
    public final Q b() {
        if (this.a && ((androidx.work.impl.model.q) this.c).j.d) {
            throw new IllegalArgumentException("Cannot set backoff criteria on an idle mode job");
        }
        if (((androidx.work.impl.model.q) this.c).q) {
            throw new IllegalArgumentException("PeriodicWorkRequests cannot be expedited");
        }
        Intrinsics.checkNotNullParameter(this, "builder");
        return new L((UUID) this.b, (androidx.work.impl.model.q) this.c, (Set) this.d);
    }

    @Override // androidx.camera.view.j
    public final androidx.camera.view.j e() {
        return this;
    }
}
