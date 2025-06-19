package androidx.lifecycle;

import com.google.android.gms.internal.mlkit_vision_camera.C1;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A0 {
    public static final com.onetrust.otpublishers.headless.Internal.Helper.h b = new com.onetrust.otpublishers.headless.Internal.Helper.h(4);
    public final Object a;

    public A0() {
        this.a = new AtomicReference(null);
    }

    public w0 a(Class modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "<this>");
        return b(kotlin.jvm.internal.K.a(modelClass));
    }

    public w0 b(C4950i modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        return ((com.quizlet.data.repository.metering.j) this.a).e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB));
    }

    public A0(B0 store, y0 factory, androidx.lifecycle.viewmodel.c defaultCreationExtras) {
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        this.a = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
    }

    public A0(d0 d0Var) {
        this.a = d0Var;
    }
}
