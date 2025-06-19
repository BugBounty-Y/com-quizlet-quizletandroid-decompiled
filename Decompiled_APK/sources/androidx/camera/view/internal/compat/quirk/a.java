package androidx.camera.view.internal.compat.quirk;

import androidx.appcompat.app.Q;
import androidx.camera.core.impl.g0;
import androidx.camera.core.impl.i0;
import com.google.android.gms.internal.mlkit_vision_barcode.T;

/* loaded from: classes.dex */
public abstract class a {
    public static volatile i0 a;

    static {
        g0 g0Var = g0.c;
        androidx.camera.core.impl.utils.executor.a aVarA = T.a();
        androidx.camera.camera2.internal.compat.quirk.a aVar = new androidx.camera.camera2.internal.compat.quirk.a(4);
        g0Var.getClass();
        g0Var.a.c(aVarA, new Q(aVar));
    }
}
