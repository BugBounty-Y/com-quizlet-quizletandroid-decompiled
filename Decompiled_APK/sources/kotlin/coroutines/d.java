package kotlin.coroutines;

import java.io.Serializable;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class d implements Serializable {

    @NotNull
    public static final c b = new c(null);
    public final CoroutineContext[] a;

    public d(CoroutineContext[] elements) {
        Intrinsics.checkNotNullParameter(elements, "elements");
        this.a = elements;
    }

    private final Object readResolve() {
        CoroutineContext coroutineContextPlus = n.a;
        for (CoroutineContext coroutineContext : this.a) {
            coroutineContextPlus = coroutineContextPlus.plus(coroutineContext);
        }
        return coroutineContextPlus;
    }
}
