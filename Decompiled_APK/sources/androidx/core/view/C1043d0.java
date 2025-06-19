package androidx.core.view;

import android.view.View;
import java.lang.ref.WeakReference;

/* renamed from: androidx.core.view.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1043d0 {
    public final WeakReference a;

    public C1043d0(View view) {
        this.a = new WeakReference(view);
    }

    public final void a(float f) {
        View view = (View) this.a.get();
        if (view != null) {
            view.animate().alpha(f);
        }
    }

    public final void b() {
        View view = (View) this.a.get();
        if (view != null) {
            view.animate().cancel();
        }
    }

    public final void c(long j) {
        View view = (View) this.a.get();
        if (view != null) {
            view.animate().setDuration(j);
        }
    }

    public final void d(InterfaceC1045e0 interfaceC1045e0) {
        View view = (View) this.a.get();
        if (view != null) {
            if (interfaceC1045e0 != null) {
                view.animate().setListener(new C1041c0(0, interfaceC1045e0, view));
            } else {
                view.animate().setListener(null);
            }
        }
    }

    public final void e(float f) {
        View view = (View) this.a.get();
        if (view != null) {
            view.animate().translationY(f);
        }
    }
}
