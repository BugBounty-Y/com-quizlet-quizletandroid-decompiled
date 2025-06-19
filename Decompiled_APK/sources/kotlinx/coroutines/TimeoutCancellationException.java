package kotlinx.coroutines;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes3.dex */
public final class TimeoutCancellationException extends CancellationException implements InterfaceC5037v {
    public final transient E0 a;

    public TimeoutCancellationException(String str, E0 e0) {
        super(str);
        this.a = e0;
    }

    @Override // kotlinx.coroutines.InterfaceC5037v
    public final Throwable a() {
        String message = getMessage();
        if (message == null) {
            message = "";
        }
        TimeoutCancellationException timeoutCancellationException = new TimeoutCancellationException(message, this.a);
        timeoutCancellationException.initCause(this);
        return timeoutCancellationException;
    }
}
