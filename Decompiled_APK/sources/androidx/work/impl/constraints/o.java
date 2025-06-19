package androidx.work.impl.constraints;

import androidx.work.impl.model.q;
import androidx.work.z;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public abstract class o {
    public static final /* synthetic */ int a = 0;

    static {
        Intrinsics.checkNotNullExpressionValue(z.e("WorkConstraintsTracker"), "tagWithPrefix(\"WorkConstraintsTracker\")");
    }

    public static final y0 a(m mVar, q spec, AbstractC5040y dispatcher, j listener) {
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        Intrinsics.checkNotNullParameter(spec, "spec");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(listener, "listener");
        return E.A(E.c(dispatcher), null, null, new n(mVar, spec, listener, null), 3);
    }
}
