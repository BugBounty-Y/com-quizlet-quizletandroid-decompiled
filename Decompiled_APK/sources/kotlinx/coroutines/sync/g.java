package kotlinx.coroutines.sync;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes3.dex */
public final /* synthetic */ class g extends C4956o implements Function2 {
    public static final g a = new g(2, j.class, "createSegment", "createSegment(JLkotlinx/coroutines/sync/SemaphoreSegment;)Lkotlinx/coroutines/sync/SemaphoreSegment;", 1);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = j.a;
        return new k(((Number) obj).longValue(), (k) obj2, 0);
    }
}
