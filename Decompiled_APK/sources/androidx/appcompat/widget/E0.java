package androidx.appcompat.widget;

import android.os.Handler;
import android.widget.AbsListView;

/* loaded from: classes.dex */
public final class E0 implements AbsListView.OnScrollListener {
    public final /* synthetic */ G0 a;

    public E0(G0 g0) {
        this.a = g0;
    }

    @Override // android.widget.AbsListView.OnScrollListener
    public final void onScroll(AbsListView absListView, int i, int i2, int i3) {
    }

    @Override // android.widget.AbsListView.OnScrollListener
    public final void onScrollStateChanged(AbsListView absListView, int i) {
        if (i == 1) {
            G0 g0 = this.a;
            if (g0.z.getInputMethodMode() == 2 || g0.z.getContentView() == null) {
                return;
            }
            Handler handler = g0.v;
            C0 c0 = g0.r;
            handler.removeCallbacks(c0);
            c0.run();
        }
    }
}
