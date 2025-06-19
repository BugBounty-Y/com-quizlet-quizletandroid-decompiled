package androidx.lifecycle;

import androidx.activity.C0034f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n0 implements H, AutoCloseable {
    public final String a;
    public final m0 b;
    public boolean c;

    public n0(String key, m0 handle) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(handle, "handle");
        this.a = key;
        this.b = handle;
    }

    public final void a(C lifecycle, androidx.savedstate.d registry) {
        Intrinsics.checkNotNullParameter(registry, "registry");
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        if (this.c) {
            throw new IllegalStateException("Already attached to lifecycleOwner");
        }
        this.c = true;
        lifecycle.a(this);
        registry.c(this.a, (C0034f) this.b.b.f);
    }

    @Override // java.lang.AutoCloseable
    public final void close() {
    }

    @Override // androidx.lifecycle.H
    public final void d(J source, A event) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(event, "event");
        if (event == A.ON_DESTROY) {
            this.c = false;
            source.getLifecycle().b(this);
        }
    }
}
