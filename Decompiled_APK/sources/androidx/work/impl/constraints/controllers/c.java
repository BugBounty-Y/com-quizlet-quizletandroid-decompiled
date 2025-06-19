package androidx.work.impl.constraints.controllers;

import androidx.work.C1425f;
import androidx.work.impl.model.q;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public abstract class c implements e {
    public final androidx.work.impl.constraints.trackers.e a;

    public c(androidx.work.impl.constraints.trackers.e tracker) {
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        this.a = tracker;
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final C4986c a(C1425f constraints) {
        Intrinsics.checkNotNullParameter(constraints, "constraints");
        return e0.g(new b(this, null));
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final boolean c(q workSpec) {
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        return b(workSpec) && e(this.a.c());
    }

    public abstract int d();

    public abstract boolean e(Object obj);
}
