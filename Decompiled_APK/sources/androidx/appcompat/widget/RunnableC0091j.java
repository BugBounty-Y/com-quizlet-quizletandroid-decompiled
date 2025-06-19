package androidx.appcompat.widget;

import android.view.View;

/* renamed from: androidx.appcompat.widget.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC0091j implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ RunnableC0091j(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        androidx.appcompat.view.menu.l lVar;
        switch (this.a) {
            case 0:
                C0095l c0095l = (C0095l) this.c;
                androidx.appcompat.view.menu.n nVar = c0095l.c;
                if (nVar != null && (lVar = nVar.e) != null) {
                    lVar.D(nVar);
                }
                View view = (View) c0095l.h;
                if (view != null && view.getWindowToken() != null) {
                    C0087h c0087h = (C0087h) this.b;
                    if (c0087h.b()) {
                        c0095l.s = c0087h;
                    } else if (c0087h.e != null) {
                        c0087h.d(0, 0, false, false);
                        c0095l.s = c0087h;
                    }
                }
                c0095l.u = null;
                break;
            default:
                View view2 = (View) this.b;
                int left = view2.getLeft();
                T0 t0 = (T0) this.c;
                t0.smoothScrollTo(left - ((t0.getWidth() - view2.getWidth()) / 2), 0);
                t0.a = null;
                break;
        }
    }
}
