package androidx.compose.ui;

import java.util.concurrent.CancellationException;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
public final class ModifierNodeDetachedCancellationException extends CancellationException {
    public ModifierNodeDetachedCancellationException() {
        super("The Modifier.Node was detached");
    }

    @Override // java.lang.Throwable
    public final Throwable fillInStackTrace() {
        setStackTrace(a.e);
        return this;
    }
}
