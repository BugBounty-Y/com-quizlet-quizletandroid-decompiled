package androidx.core.view;

import android.content.Context;
import android.util.Log;
import android.view.View;

/* renamed from: androidx.core.view.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1040c {
    public com.airbnb.lottie.network.d a;

    public AbstractC1040c(Context context) {
    }

    public boolean a() {
        return false;
    }

    public boolean b() {
        return true;
    }

    public abstract View c();

    public View d(androidx.appcompat.view.menu.p pVar) {
        return c();
    }

    public boolean e() {
        return false;
    }

    public void f(androidx.appcompat.view.menu.F f) {
    }

    public boolean g() {
        return false;
    }

    public void h(com.airbnb.lottie.network.d dVar) {
        if (this.a != null) {
            Log.w("ActionProvider(support)", "setVisibilityListener: Setting a new ActionProvider.VisibilityListener when one is already set. Are you reusing this " + getClass().getSimpleName() + " instance while it is still in use somewhere else?");
        }
        this.a = dVar;
    }
}
