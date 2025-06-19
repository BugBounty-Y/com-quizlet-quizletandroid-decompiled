package androidx.work.impl.constraints.controllers;

import androidx.work.A;
import androidx.work.impl.constraints.i;
import androidx.work.impl.model.q;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g extends c {
    public final int b;

    static {
        Intrinsics.checkNotNullExpressionValue(z.e("NetworkNotRoamingCtrlr"), "tagWithPrefix(\"NetworkNotRoamingCtrlr\")");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(androidx.work.impl.constraints.trackers.g tracker) {
        super(tracker);
        Intrinsics.checkNotNullParameter(tracker, "tracker");
        this.b = 7;
    }

    @Override // androidx.work.impl.constraints.controllers.e
    public final boolean b(q workSpec) {
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        return workSpec.j.a == A.d;
    }

    @Override // androidx.work.impl.constraints.controllers.c
    public final int d() {
        return this.b;
    }

    @Override // androidx.work.impl.constraints.controllers.c
    public final boolean e(Object obj) {
        i value = (i) obj;
        Intrinsics.checkNotNullParameter(value, "value");
        return (value.a && value.d) ? false : true;
    }
}
