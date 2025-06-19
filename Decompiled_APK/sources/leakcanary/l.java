package leakcanary;

import android.view.View;
import android.view.inputmethod.InputMethodManager;
import java.lang.reflect.Field;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class l implements curtains.c {
    public final /* synthetic */ Field a;
    public final /* synthetic */ InputMethodManager b;

    public l(Field field, InputMethodManager inputMethodManager) {
        this.a = field;
        this.b = inputMethodManager;
    }

    @Override // curtains.c
    public final void a(View removedRootView, boolean z) throws IllegalAccessException, IllegalArgumentException {
        Intrinsics.f(removedRootView, "view");
        Intrinsics.checkNotNullParameter(removedRootView, "view");
        if (z) {
            return;
        }
        Intrinsics.f(removedRootView, "removedRootView");
        Field field = this.a;
        InputMethodManager inputMethodManager = this.b;
        if (((View) field.get(inputMethodManager)) == removedRootView) {
            field.set(inputMethodManager, null);
        }
    }
}
