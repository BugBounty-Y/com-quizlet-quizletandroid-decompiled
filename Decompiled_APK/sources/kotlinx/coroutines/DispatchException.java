package kotlinx.coroutines;

import kotlin.Metadata;
import kotlin.coroutines.CoroutineContext;

@Metadata
/* loaded from: classes3.dex */
public final class DispatchException extends Exception {
    public final Throwable a;

    public DispatchException(Throwable th, AbstractC5040y abstractC5040y, CoroutineContext coroutineContext) {
        super("Coroutine dispatcher " + abstractC5040y + " threw an exception, context = " + coroutineContext, th);
        this.a = th;
    }

    @Override // java.lang.Throwable
    public final Throwable getCause() {
        return this.a;
    }
}
