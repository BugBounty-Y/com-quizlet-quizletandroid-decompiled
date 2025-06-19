package androidx.compose.foundation.text.input.internal;

import android.view.inputmethod.EditorInfo;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class o {
    public static final o a = new o();

    public final void a(@NotNull EditorInfo editorInfo) {
        editorInfo.setSupportedHandwritingGestures(kotlin.collections.B.j(androidx.camera.camera2.internal.compat.j.n(), androidx.camera.camera2.internal.compat.j.x(), androidx.camera.camera2.internal.compat.j.t(), androidx.camera.camera2.internal.compat.j.v(), androidx.camera.camera2.internal.compat.j.z(), androidx.camera.camera2.internal.compat.j.B(), androidx.camera.camera2.internal.compat.j.D()));
        Class[] elements = {androidx.camera.camera2.internal.compat.j.n(), androidx.camera.camera2.internal.compat.j.x(), androidx.camera.camera2.internal.compat.j.t(), androidx.camera.camera2.internal.compat.j.v()};
        Intrinsics.checkNotNullParameter(elements, "elements");
        editorInfo.setSupportedHandwritingGesturePreviews(C4933y.T(elements));
    }
}
