package androidx.lifecycle.viewmodel.internal;

import androidx.lifecycle.viewmodel.e;
import androidx.lifecycle.w0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements y0 {
    public static final b a = new b();

    @Override // androidx.lifecycle.y0
    public final w0 c(C4950i modelClass, e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return A1.h(kotlin.jvm.a.b(modelClass));
    }
}
