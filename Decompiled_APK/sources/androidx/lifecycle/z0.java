package androidx.lifecycle;

import com.google.android.gms.internal.mlkit_vision_camera.A1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class z0 implements y0 {
    public static z0 a;

    @Override // androidx.lifecycle.y0
    public w0 a(Class modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        return A1.h(modelClass);
    }

    @Override // androidx.lifecycle.y0
    public w0 b(Class modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return a(modelClass);
    }

    @Override // androidx.lifecycle.y0
    public final w0 c(C4950i modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        return b(kotlin.jvm.a.b(modelClass), extras);
    }
}
