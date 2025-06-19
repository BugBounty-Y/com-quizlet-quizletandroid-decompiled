package kotlin.coroutines;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class k {
    public static CoroutineContext.Element a(CoroutineContext.Element element, l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (Intrinsics.b(element.getKey(), key)) {
            return element;
        }
        return null;
    }

    public static CoroutineContext b(CoroutineContext.Element element, l key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return Intrinsics.b(element.getKey(), key) ? n.a : element;
    }

    public static CoroutineContext c(CoroutineContext context, CoroutineContext.Element element) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        return context == n.a ? element : (CoroutineContext) context.fold(element, m.a);
    }
}
