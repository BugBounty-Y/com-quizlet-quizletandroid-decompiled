package androidx.compose.ui.platform;

import android.view.Choreographer;
import kotlin.jvm.functions.Function1;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.compose.ui.platform.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ChoreographerFrameCallbackC0931a0 implements Choreographer.FrameCallback {
    public final /* synthetic */ C5028l a;
    public final /* synthetic */ Function1 b;

    public ChoreographerFrameCallbackC0931a0(C5028l c5028l, C0933b0 c0933b0, Function1 function1) {
        this.a = c5028l;
        this.b = function1;
    }

    @Override // android.view.Choreographer.FrameCallback
    public final void doFrame(long j) {
        Object objB;
        Function1 function1 = this.b;
        try {
            kotlin.p pVar = kotlin.r.b;
            objB = function1.invoke(Long.valueOf(j));
        } catch (Throwable th) {
            kotlin.p pVar2 = kotlin.r.b;
            objB = androidx.glance.appwidget.protobuf.Z.b(th);
        }
        this.a.resumeWith(objB);
    }
}
