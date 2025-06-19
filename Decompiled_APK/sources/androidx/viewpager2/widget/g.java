package androidx.viewpager2.widget;

import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.C1383o0;
import androidx.recyclerview.widget.InterfaceC1385p0;

/* loaded from: classes.dex */
public final class g implements InterfaceC1385p0 {
    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void b(View view) {
    }

    @Override // androidx.recyclerview.widget.InterfaceC1385p0
    public final void c(View view) {
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        if (((ViewGroup.MarginLayoutParams) c1383o0).width != -1 || ((ViewGroup.MarginLayoutParams) c1383o0).height != -1) {
            throw new IllegalStateException("Pages must fill the whole ViewPager2 (use match_parent)");
        }
    }
}
