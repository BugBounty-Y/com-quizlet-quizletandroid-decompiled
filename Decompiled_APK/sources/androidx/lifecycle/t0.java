package androidx.lifecycle;

import android.app.Application;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.List;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class t0 {
    public static final List a = kotlin.collections.B.j(Application.class, m0.class);
    public static final List b = kotlin.collections.A.b(m0.class);

    public static final Constructor a(Class modelClass, List signature) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(signature, "signature");
        androidx.collection.Y yF = kotlin.jvm.internal.O.f(modelClass.getConstructors());
        while (yF.hasNext()) {
            Constructor constructor = (Constructor) yF.next();
            Class<?>[] parameterTypes = constructor.getParameterTypes();
            Intrinsics.checkNotNullExpressionValue(parameterTypes, "getParameterTypes(...)");
            List listP = C4933y.P(parameterTypes);
            if (Intrinsics.b(signature, listP)) {
                return constructor;
            }
            if (signature.size() == listP.size() && listP.containsAll(signature)) {
                throw new UnsupportedOperationException("Class " + modelClass.getSimpleName() + " must have parameters in the proper order: " + signature);
            }
        }
        return null;
    }

    public static final w0 b(Class modelClass, Constructor constructor, Object... params) {
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(constructor, "constructor");
        Intrinsics.checkNotNullParameter(params, "params");
        try {
            return (w0) constructor.newInstance(Arrays.copyOf(params, params.length));
        } catch (IllegalAccessException e) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "Failed to access "), e);
        } catch (InstantiationException e2) {
            throw new RuntimeException("A " + modelClass + " cannot be instantiated.", e2);
        } catch (InvocationTargetException e3) {
            throw new RuntimeException(androidx.compose.ui.node.B.d(modelClass, "An exception happened in constructor of "), e3.getCause());
        }
    }
}
