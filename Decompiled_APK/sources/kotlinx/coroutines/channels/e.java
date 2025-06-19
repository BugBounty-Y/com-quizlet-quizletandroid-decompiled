package kotlinx.coroutines.channels;

import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes3.dex */
public final /* synthetic */ class e extends C4956o implements kotlin.jvm.functions.c {
    public static final e a = new e(3, h.class, "processResultSelectReceiveCatching", "processResultSelectReceiveCatching(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", 0);

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        h hVar = (h) obj;
        AtomicLongFieldUpdater atomicLongFieldUpdater = h.b;
        hVar.getClass();
        if (obj3 == j.l) {
            obj3 = new m(hVar.r());
        }
        return new o(obj3);
    }
}
