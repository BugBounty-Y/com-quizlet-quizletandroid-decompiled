package okio;

import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H extends I {
    @Override // okio.I
    public final I d(long j) {
        return this;
    }

    @Override // okio.I
    public final void f() {
    }

    @Override // okio.I
    public final I g(long j, TimeUnit unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        return this;
    }
}
