package androidx.compose.foundation.layout;

import android.os.Build;
import android.view.View;
import androidx.core.view.C1054k;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class S0 {
    public static final WeakHashMap w = new WeakHashMap();
    public final C0378c a = C0380d.b(4, "captionBar");
    public final C0378c b;
    public final C0378c c;
    public final C0378c d;
    public final C0378c e;
    public final C0378c f;
    public final C0378c g;
    public final C0378c h;
    public final C0378c i;
    public final P0 j;
    public final M0 k;
    public final M0 l;
    public final P0 m;
    public final P0 n;
    public final P0 o;
    public final P0 p;
    public final P0 q;
    public final P0 r;
    public final P0 s;
    public final boolean t;
    public int u;
    public final RunnableC0403o0 v;

    public S0(View view) {
        C0378c c0378cB = C0380d.b(128, "displayCutout");
        this.b = c0378cB;
        C0378c c0378cB2 = C0380d.b(8, "ime");
        this.c = c0378cB2;
        C0378c c0378cB3 = C0380d.b(32, "mandatorySystemGestures");
        this.d = c0378cB3;
        this.e = C0380d.b(2, "navigationBars");
        this.f = C0380d.b(1, "statusBars");
        C0378c c0378cB4 = C0380d.b(519, "systemBars");
        this.g = c0378cB4;
        C0378c c0378cB5 = C0380d.b(16, "systemGestures");
        this.h = c0378cB5;
        C0378c c0378cB6 = C0380d.b(64, "tappableElement");
        this.i = c0378cB6;
        P0 p0 = new P0(new C0408r0(0, 0, 0, 0), "waterfall");
        this.j = p0;
        M0 m0 = new M0(new M0(c0378cB4, c0378cB2), c0378cB);
        this.k = m0;
        this.l = new M0(m0, new M0(new M0(new M0(c0378cB6, c0378cB3), c0378cB5), p0));
        this.m = C0380d.d(4, "captionBarIgnoringVisibility");
        this.n = C0380d.d(2, "navigationBarsIgnoringVisibility");
        this.o = C0380d.d(1, "statusBarsIgnoringVisibility");
        this.p = C0380d.d(519, "systemBarsIgnoringVisibility");
        this.q = C0380d.d(64, "tappableElementIgnoringVisibility");
        this.r = C0380d.d(8, "imeAnimationTarget");
        this.s = C0380d.d(8, "imeAnimationSource");
        Object parent = view.getParent();
        View view2 = parent instanceof View ? (View) parent : null;
        Object tag = view2 != null ? view2.getTag(R.id.consume_window_insets_tag) : null;
        Boolean bool = tag instanceof Boolean ? (Boolean) tag : null;
        this.t = bool != null ? bool.booleanValue() : true;
        this.v = new RunnableC0403o0(this);
    }

    public static void a(S0 s0, androidx.core.view.D0 d0) {
        boolean z = false;
        s0.a.f(d0, 0);
        s0.c.f(d0, 0);
        s0.b.f(d0, 0);
        s0.e.f(d0, 0);
        s0.f.f(d0, 0);
        s0.g.f(d0, 0);
        s0.h.f(d0, 0);
        s0.i.f(d0, 0);
        s0.d.f(d0, 0);
        s0.m.f(AbstractC0382e.A(d0.a.h(4)));
        s0.n.f(AbstractC0382e.A(d0.a.h(2)));
        s0.o.f(AbstractC0382e.A(d0.a.h(1)));
        s0.p.f(AbstractC0382e.A(d0.a.h(519)));
        s0.q.f(AbstractC0382e.A(d0.a.h(64)));
        C1054k c1054kF = d0.a.f();
        if (c1054kF != null) {
            s0.j.f(AbstractC0382e.A(Build.VERSION.SDK_INT >= 30 ? androidx.core.graphics.e.c(androidx.camera.core.impl.utils.d.e(c1054kF.a)) : androidx.core.graphics.e.e));
        }
        synchronized (androidx.compose.runtime.snapshots.m.b) {
            androidx.collection.J j = androidx.compose.runtime.snapshots.m.i.h;
            if (j != null) {
                if (j.h()) {
                    z = true;
                }
            }
        }
        if (z) {
            androidx.compose.runtime.snapshots.m.a();
        }
    }
}
