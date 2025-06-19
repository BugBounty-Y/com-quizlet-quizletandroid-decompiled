package androidx.lifecycle;

import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public interface y0 {
    default w0 a(Class modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        throw new UnsupportedOperationException("`Factory.create(String, CreationExtras)` is not implemented. You may need to override the method and provide a custom implementation. Note that using `Factory.create(String)` is not supported and considered an error.");
    }

    default w0 b(Class modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return a(modelClass);
    }

    default w0 c(C4950i modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return b(kotlin.jvm.a.b(modelClass), extras);
    }
}
