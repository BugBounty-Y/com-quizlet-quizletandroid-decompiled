package kotlin.coroutines;

import kotlin.Metadata;
import kotlin.jvm.functions.Function2;

@Metadata
/* loaded from: classes3.dex */
public interface CoroutineContext {

    @Metadata
    public interface Element extends CoroutineContext {
        l getKey();
    }

    Object fold(Object obj, Function2 function2);

    Element get(l lVar);

    CoroutineContext minusKey(l lVar);

    CoroutineContext plus(CoroutineContext coroutineContext);
}
