package androidx.appcompat.widget;

import android.content.Context;
import android.os.Build;
import android.util.Log;
import android.widget.PopupWindow;
import java.lang.reflect.Method;

/* loaded from: classes.dex */
public final class L0 extends G0 implements H0 {
    public static final Method D;
    public com.airbnb.lottie.network.c C;

    static {
        try {
            if (Build.VERSION.SDK_INT <= 28) {
                D = PopupWindow.class.getDeclaredMethod("setTouchModal", Boolean.TYPE);
            }
        } catch (NoSuchMethodException unused) {
            Log.i("MenuPopupWindow", "Could not find method setTouchModal() on PopupWindow. Oh well.");
        }
    }

    @Override // androidx.appcompat.widget.H0
    public final void c(androidx.appcompat.view.menu.n nVar, androidx.appcompat.view.menu.p pVar) {
        com.airbnb.lottie.network.c cVar = this.C;
        if (cVar != null) {
            cVar.c(nVar, pVar);
        }
    }

    @Override // androidx.appcompat.widget.H0
    public final void o(androidx.appcompat.view.menu.n nVar, androidx.appcompat.view.menu.p pVar) {
        com.airbnb.lottie.network.c cVar = this.C;
        if (cVar != null) {
            cVar.o(nVar, pVar);
        }
    }

    @Override // androidx.appcompat.widget.G0
    public final C0113u0 q(Context context, boolean z) {
        K0 k0 = new K0(context, z);
        k0.setHoverListener(this);
        return k0;
    }
}
