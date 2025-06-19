package kotlinx.serialization;

import com.quizlet.remote.model.school.h;
import com.quizlet.ui.compose.C4830x;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.internal.AbstractC5059m;
import kotlinx.serialization.internal.InterfaceC5045b0;
import kotlinx.serialization.internal.m0;

/* loaded from: classes3.dex */
public abstract class g {
    public static final m0 a;
    public static final m0 b;
    public static final InterfaceC5045b0 c;
    public static final InterfaceC5045b0 d;

    static {
        com.sdk.growthbook.utils.a factory = new com.sdk.growthbook.utils.a(22);
        boolean z = AbstractC5059m.a;
        Intrinsics.checkNotNullParameter(factory, "factory");
        boolean z2 = AbstractC5059m.a;
        a = z2 ? new com.quizlet.remote.model.report.c(factory) : new com.quizlet.remote.model.search.d(factory);
        com.sdk.growthbook.utils.a factory2 = new com.sdk.growthbook.utils.a(23);
        Intrinsics.checkNotNullParameter(factory2, "factory");
        b = z2 ? new com.quizlet.remote.model.report.c(factory2) : new com.quizlet.remote.model.search.d(factory2);
        C4830x factory3 = new C4830x(22, (byte) 0);
        Intrinsics.checkNotNullParameter(factory3, "factory");
        c = z2 ? new h(factory3) : new com.quizlet.remote.model.set.d(factory3);
        C4830x factory4 = new C4830x(23, (byte) 0);
        Intrinsics.checkNotNullParameter(factory4, "factory");
        d = z2 ? new h(factory4) : new com.quizlet.remote.model.set.d(factory4);
    }
}
