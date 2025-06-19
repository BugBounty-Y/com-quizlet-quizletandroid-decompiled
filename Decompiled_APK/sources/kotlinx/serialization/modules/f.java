package kotlinx.serialization.modules;

import androidx.camera.camera2.internal.p0;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class f {
    public static final p0 a = new p0(V.c(), V.c(), V.c(), V.c(), V.c(), false);

    public static final p0 a(p0 module, p0 module2) {
        Intrinsics.checkNotNullParameter(module, "<this>");
        Intrinsics.checkNotNullParameter(module2, "other");
        p0 p0Var = new p0();
        Intrinsics.checkNotNullParameter(module, "module");
        module.h(p0Var);
        Intrinsics.checkNotNullParameter(module2, "module");
        module2.h(p0Var);
        return p0Var.g();
    }
}
