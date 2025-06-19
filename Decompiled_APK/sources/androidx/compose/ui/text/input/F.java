package androidx.compose.ui.text.input;

import android.view.Choreographer;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final /* synthetic */ class F implements Executor {
    public final /* synthetic */ Choreographer a;

    @Override // java.util.concurrent.Executor
    public final void execute(final Runnable runnable) {
        this.a.postFrameCallback(new Choreographer.FrameCallback() { // from class: androidx.compose.ui.text.input.G
            @Override // android.view.Choreographer.FrameCallback
            public final void doFrame(long j) {
                runnable.run();
            }
        });
    }
}
