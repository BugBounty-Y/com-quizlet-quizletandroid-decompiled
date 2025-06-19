package androidx.compose.foundation.text.input.internal;

import android.os.CancellationSignal;
import android.view.inputmethod.HandwritingGesture;
import android.view.inputmethod.PreviewableHandwritingGesture;
import androidx.camera.camera2.internal.RunnableC0133j;
import androidx.compose.foundation.text.C0492h0;
import androidx.compose.foundation.text.selection.i0;
import androidx.compose.ui.platform.Y0;
import androidx.compose.ui.text.input.InterfaceC1006i;
import java.util.concurrent.Executor;
import java.util.function.IntConsumer;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class h {
    public static final h a = new h();

    public final void a(C0492h0 c0492h0, i0 i0Var, @NotNull HandwritingGesture handwritingGesture, Y0 y0, Executor executor, IntConsumer intConsumer, @NotNull Function1<? super InterfaceC1006i, Unit> function1) {
        int i = c0492h0 != null ? s.a.i(c0492h0, handwritingGesture, i0Var, y0, function1) : 3;
        if (intConsumer == null) {
            return;
        }
        if (executor != null) {
            executor.execute(new RunnableC0133j(intConsumer, i, 2));
        } else {
            intConsumer.accept(i);
        }
    }

    public final boolean b(C0492h0 c0492h0, i0 i0Var, @NotNull PreviewableHandwritingGesture previewableHandwritingGesture, CancellationSignal cancellationSignal) {
        if (c0492h0 != null) {
            return s.a.A(c0492h0, previewableHandwritingGesture, i0Var, cancellationSignal);
        }
        return false;
    }
}
