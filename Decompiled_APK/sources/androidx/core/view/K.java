package androidx.core.view;

import android.os.Build;
import android.view.View;
import android.view.WindowInsets;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class K implements View.OnApplyWindowInsetsListener {
    public D0 a = null;
    public final /* synthetic */ View b;
    public final /* synthetic */ InterfaceC1062t c;

    public K(View view, InterfaceC1062t interfaceC1062t) {
        this.b = view;
        this.c = interfaceC1062t;
    }

    @Override // android.view.View.OnApplyWindowInsetsListener
    public WindowInsets onApplyWindowInsets(View view, WindowInsets windowInsets) {
        D0 d0H = D0.h(view, windowInsets);
        int i = Build.VERSION.SDK_INT;
        InterfaceC1062t interfaceC1062t = this.c;
        if (i < 30) {
            L.a(windowInsets, this.b);
            if (d0H.equals(this.a)) {
                return interfaceC1062t.w(d0H, view).g();
            }
        }
        this.a = d0H;
        D0 d0W = interfaceC1062t.w(d0H, view);
        if (i >= 30) {
            return d0W.g();
        }
        WeakHashMap weakHashMap = V.a;
        J.c(view);
        return d0W.g();
    }
}
