package androidx.work;

import android.content.Context;
import java.util.Collections;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class WorkManagerInitializer implements androidx.startup.b {
    static {
        z.e("WrkMgrInitializer");
    }

    @Override // androidx.startup.b
    public final Object create(Context context) {
        z.c().getClass();
        C1422c configuration = new C1422c(new G());
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(configuration, "configuration");
        androidx.work.impl.r.i(context, configuration);
        Intrinsics.checkNotNullParameter(context, "context");
        androidx.work.impl.r rVarH = androidx.work.impl.r.h(context);
        Intrinsics.checkNotNullExpressionValue(rVarH, "getInstance(context)");
        return rVarH;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return Collections.EMPTY_LIST;
    }
}
