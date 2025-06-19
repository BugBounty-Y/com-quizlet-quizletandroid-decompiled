package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class I {
    public final C1351y0 a;
    public final com.quizlet.remote.model.notes.e b;

    public I(androidx.lifecycle.viewmodel.internal.a scope, C1351y0 parent) {
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(parent, "parent");
        this.a = parent;
        this.b = new com.quizlet.remote.model.notes.e(parent.a, scope);
    }
}
