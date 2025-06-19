package leakcanary;

import android.app.Application;
import android.os.Build;
import android.view.inputmethod.InputMethodManager;
import java.lang.reflect.Field;
import kotlin.TypeCastException;

/* loaded from: classes3.dex */
public final class m extends w {
    public m() {
        super("IMM_CUR_ROOT_VIEW", 12);
    }

    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.Object, kotlin.k] */
    @Override // leakcanary.w
    public final void a(Application application) {
        if (Build.VERSION.SDK_INT >= 29) {
            return;
        }
        try {
            Object systemService = application.getSystemService("input_method");
            if (systemService == null) {
                throw new TypeCastException("null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
            }
            InputMethodManager inputMethodManager = (InputMethodManager) systemService;
            Field declaredField = InputMethodManager.class.getDeclaredField("mCurRootView");
            declaredField.setAccessible(true);
            application.registerActivityLifecycleCallbacks(new k(this, declaredField, inputMethodManager));
            ((curtains.internal.b) curtains.b.a.getValue()).a.add(new l(declaredField, inputMethodManager));
        } catch (Throwable unused) {
        }
    }
}
