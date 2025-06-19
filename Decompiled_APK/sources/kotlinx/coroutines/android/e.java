package kotlinx.coroutines.android;

import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.view.Choreographer;
import androidx.glance.appwidget.protobuf.Z;
import java.lang.reflect.InvocationTargetException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.p;
import kotlin.q;
import kotlin.r;

/* loaded from: classes3.dex */
public abstract class e {
    public static final /* synthetic */ int a = 0;
    private static volatile Choreographer choreographer;

    static {
        Object objB;
        try {
            p pVar = r.b;
            objB = new d(a(Looper.getMainLooper()));
        } catch (Throwable th) {
            p pVar2 = r.b;
            objB = Z.b(th);
        }
        if (objB instanceof q) {
            objB = null;
        }
    }

    public static final Handler a(Looper looper) throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        if (Build.VERSION.SDK_INT >= 28) {
            Object objInvoke = Handler.class.getDeclaredMethod("createAsync", Looper.class).invoke(null, looper);
            Intrinsics.e(objInvoke, "null cannot be cast to non-null type android.os.Handler");
            return (Handler) objInvoke;
        }
        try {
            return (Handler) Handler.class.getDeclaredConstructor(Looper.class, Handler.Callback.class, Boolean.TYPE).newInstance(looper, null, Boolean.TRUE);
        } catch (NoSuchMethodException unused) {
            return new Handler(looper);
        }
    }
}
