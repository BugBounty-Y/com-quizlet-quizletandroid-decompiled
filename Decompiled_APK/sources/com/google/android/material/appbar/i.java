package com.google.android.material.appbar;

import android.view.View;
import android.widget.FrameLayout;
import androidx.core.view.D0;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class i implements f {
    public final /* synthetic */ CollapsingToolbarLayout a;

    public i(CollapsingToolbarLayout collapsingToolbarLayout) {
        this.a = collapsingToolbarLayout;
    }

    @Override // com.google.android.material.appbar.f
    public final void a(AppBarLayout appBarLayout, int i) {
        CollapsingToolbarLayout collapsingToolbarLayout = this.a;
        collapsingToolbarLayout.y = i;
        D0 d0 = collapsingToolbarLayout.A;
        int iD = d0 != null ? d0.d() : 0;
        int childCount = collapsingToolbarLayout.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = collapsingToolbarLayout.getChildAt(i2);
            h hVar = (h) childAt.getLayoutParams();
            n nVarB = CollapsingToolbarLayout.b(childAt);
            int i3 = hVar.a;
            if (i3 == 1) {
                nVarB.b(AbstractC3188k6.b(-i, 0, ((collapsingToolbarLayout.getHeight() - CollapsingToolbarLayout.b(childAt).b) - childAt.getHeight()) - ((FrameLayout.LayoutParams) ((h) childAt.getLayoutParams())).bottomMargin));
            } else if (i3 == 2) {
                nVarB.b(Math.round((-i) * hVar.b));
            }
        }
        collapsingToolbarLayout.d();
        if (collapsingToolbarLayout.p != null && iD > 0) {
            WeakHashMap weakHashMap = V.a;
            collapsingToolbarLayout.postInvalidateOnAnimation();
        }
        int height = collapsingToolbarLayout.getHeight();
        WeakHashMap weakHashMap2 = V.a;
        int minimumHeight = (height - collapsingToolbarLayout.getMinimumHeight()) - iD;
        float f = minimumHeight;
        float fMin = Math.min(1.0f, (height - collapsingToolbarLayout.getScrimVisibleHeightTrigger()) / f);
        com.google.android.material.internal.b bVar = collapsingToolbarLayout.k;
        bVar.d = fMin;
        bVar.e = android.support.v4.media.session.a.a(1.0f, fMin, 0.5f, fMin);
        bVar.f = collapsingToolbarLayout.y + minimumHeight;
        bVar.p(Math.abs(i) / f);
    }
}
