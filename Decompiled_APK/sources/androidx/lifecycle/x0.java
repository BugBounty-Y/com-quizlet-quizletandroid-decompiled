package androidx.lifecycle;

import android.app.Application;
import com.google.android.gms.internal.mlkit_vision_camera.A1;
import java.lang.reflect.InvocationTargetException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class x0 extends z0 {
    public static x0 c;
    public static final com.google.mlkit.common.sdkinternal.b d = new com.google.mlkit.common.sdkinternal.b(4);
    public final Application b;

    public x0(Application application) {
        this.b = application;
    }

    @Override // androidx.lifecycle.z0, androidx.lifecycle.y0
    public final w0 a(Class modelClass) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Application application = this.b;
        if (application != null) {
            return d(modelClass, application);
        }
        throw new UnsupportedOperationException("AndroidViewModelFactory constructed with empty constructor works only with create(modelClass: Class<T>, extras: CreationExtras).");
    }

    @Override // androidx.lifecycle.z0, androidx.lifecycle.y0
    public final w0 b(Class modelClass, androidx.lifecycle.viewmodel.e extras) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(extras, "extras");
        if (this.b != null) {
            return a(modelClass);
        }
        Application application = (Application) extras.a(d);
        if (application != null) {
            return d(modelClass, application);
        }
        if (AbstractC1237a.class.isAssignableFrom(modelClass)) {
            throw new IllegalArgumentException("CreationExtras must have an application by `APPLICATION_KEY`");
        }
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        return A1.h(modelClass);
    }

    public final w0 d(Class modelClass, Application application) {
        if (!AbstractC1237a.class.isAssignableFrom(modelClass)) {
            Intrinsics.checkNotNullParameter(modelClass, "modelClass");
            return A1.h(modelClass);
        }
        try {
            w0 w0Var = (w0) modelClass.getConstructor(Application.class).newInstance(application);
            Intrinsics.d(w0Var);
            return w0Var;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e);
        } catch (InstantiationException e2) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e2);
        } catch (NoSuchMethodException e3) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e3);
        } catch (InvocationTargetException e4) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Cannot create an instance of "), e4);
        }
    }
}
