package androidx.compose.ui.scrollcapture;

import android.graphics.Rect;
import android.os.CancellationSignal;
import android.view.ScrollCaptureCallback;
import android.view.ScrollCaptureSession;
import androidx.compose.foundation.text.input.internal.q;
import androidx.compose.runtime.L0;
import androidx.compose.ui.graphics.F;
import androidx.compose.ui.semantics.o;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.function.Consumer;
import kotlinx.coroutines.E;
import kotlinx.coroutines.u0;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class f implements ScrollCaptureCallback {
    public final o a;
    public final androidx.compose.ui.unit.i b;
    public final l c;
    public final kotlinx.coroutines.internal.d d;
    public final j e;

    public f(o oVar, androidx.compose.ui.unit.i iVar, kotlinx.coroutines.internal.d dVar, l lVar) {
        this.a = oVar;
        this.b = iVar;
        this.c = lVar;
        this.d = new kotlinx.coroutines.internal.d(dVar.a.plus(h.a));
        this.e = new j(iVar.a(), new e(this, null));
    }

    /* JADX WARN: Removed duplicated region for block: B:44:0x00e4  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(androidx.compose.ui.scrollcapture.f r10, android.view.ScrollCaptureSession r11, androidx.compose.ui.unit.i r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            Method dump skipped, instructions count: 368
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.scrollcapture.f.a(androidx.compose.ui.scrollcapture.f, android.view.ScrollCaptureSession, androidx.compose.ui.unit.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final void onScrollCaptureEnd(Runnable runnable) {
        E.A(this.d, u0.a, null, new a(this, runnable, null), 2);
    }

    public final void onScrollCaptureImageRequest(ScrollCaptureSession scrollCaptureSession, CancellationSignal cancellationSignal, Rect rect, Consumer consumer) {
        y0 y0VarA = E.A(this.d, null, null, new b(this, scrollCaptureSession, rect, consumer, null), 3);
        y0VarA.Q(new g(cancellationSignal, 0));
        cancellationSignal.setOnCancelListener(new q(y0VarA, 1));
    }

    public final void onScrollCaptureSearch(CancellationSignal cancellationSignal, Consumer consumer) {
        consumer.accept(F.x(this.b));
    }

    public final void onScrollCaptureStart(ScrollCaptureSession scrollCaptureSession, CancellationSignal cancellationSignal, Runnable runnable) {
        this.e.b = DefinitionKt.NO_Float_VALUE;
        ((L0) this.c.a).setValue(Boolean.TRUE);
        runnable.run();
    }
}
