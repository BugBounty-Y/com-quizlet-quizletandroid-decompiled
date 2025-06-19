package kotlinx.coroutines;

import kotlin.coroutines.CoroutineContext;

/* loaded from: classes3.dex */
public interface A extends CoroutineContext.Element {
    void handleException(CoroutineContext coroutineContext, Throwable th);
}
