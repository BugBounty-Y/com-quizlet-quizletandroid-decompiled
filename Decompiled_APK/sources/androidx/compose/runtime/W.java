package androidx.compose.runtime;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public interface W extends CoroutineContext.Element {
    Object P(Function1 function1, kotlin.coroutines.h hVar);

    @Override // kotlin.coroutines.CoroutineContext.Element
    default kotlin.coroutines.l getKey() {
        return V.b;
    }
}
