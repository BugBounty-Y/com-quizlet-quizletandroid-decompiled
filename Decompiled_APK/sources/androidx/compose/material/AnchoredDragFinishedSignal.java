package androidx.compose.material;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class AnchoredDragFinishedSignal extends CancellationException {
    public AnchoredDragFinishedSignal() {
        super("Anchored drag finished");
    }

    @Override // java.lang.Throwable
    public final Throwable fillInStackTrace() {
        setStackTrace(new StackTraceElement[0]);
        return this;
    }
}
