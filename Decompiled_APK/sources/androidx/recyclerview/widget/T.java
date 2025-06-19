package androidx.recyclerview.widget;

import android.view.View;
import android.view.animation.DecelerateInterpolator;
import android.widget.Scroller;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public class T extends AbstractC1387q0 {
    public RecyclerView a;
    public Scroller b;
    public final I0 c = new I0(this);
    public final /* synthetic */ int d;
    public Y e;
    public Y f;

    public T(int i) {
        this.d = i;
    }

    public static int c(View view, androidx.emoji2.text.g gVar) {
        return ((gVar.c(view) / 2) + gVar.e(view)) - ((gVar.l() / 2) + gVar.k());
    }

    public static View e(AbstractC1381n0 abstractC1381n0, androidx.emoji2.text.g gVar) {
        int iV = abstractC1381n0.v();
        View view = null;
        if (iV == 0) {
            return null;
        }
        int iL = (gVar.l() / 2) + gVar.k();
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        for (int i2 = 0; i2 < iV; i2++) {
            View viewU = abstractC1381n0.u(i2);
            int iAbs = Math.abs(((gVar.c(viewU) / 2) + gVar.e(viewU)) - iL);
            if (iAbs < i) {
                view = viewU;
                i = iAbs;
            }
        }
        return view;
    }

    public static View f(AbstractC1381n0 abstractC1381n0, androidx.emoji2.text.g gVar) {
        int iV = abstractC1381n0.v();
        View view = null;
        if (iV == 0) {
            return null;
        }
        int iL = (gVar.l() / 2) + gVar.k();
        int i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        for (int i2 = 0; i2 < iV; i2++) {
            View viewU = abstractC1381n0.u(i2);
            int iAbs = Math.abs(((gVar.c(viewU) / 2) + gVar.e(viewU)) - iL);
            if (iAbs < i) {
                view = viewU;
                i = iAbs;
            }
        }
        return view;
    }

    public final void a(RecyclerView recyclerView) {
        RecyclerView recyclerView2 = this.a;
        if (recyclerView2 == recyclerView) {
            return;
        }
        I0 i0 = this.c;
        if (recyclerView2 != null) {
            ArrayList arrayList = recyclerView2.t1;
            if (arrayList != null) {
                arrayList.remove(i0);
            }
            this.a.setOnFlingListener(null);
        }
        this.a = recyclerView;
        if (recyclerView != null) {
            if (recyclerView.getOnFlingListener() != null) {
                throw new IllegalStateException("An instance of OnFlingListener already set.");
            }
            this.a.k(i0);
            this.a.setOnFlingListener(this);
            this.b = new Scroller(this.a.getContext(), new DecelerateInterpolator());
            l();
        }
    }

    public final int[] b(AbstractC1381n0 abstractC1381n0, View view) {
        switch (this.d) {
            case 0:
                int[] iArr = new int[2];
                if (abstractC1381n0.d()) {
                    androidx.emoji2.text.g gVarH = h(abstractC1381n0);
                    iArr[0] = ((gVarH.c(view) / 2) + gVarH.e(view)) - ((gVarH.l() / 2) + gVarH.k());
                } else {
                    iArr[0] = 0;
                }
                if (abstractC1381n0.e()) {
                    androidx.emoji2.text.g gVarJ = j(abstractC1381n0);
                    iArr[1] = ((gVarJ.c(view) / 2) + gVarJ.e(view)) - ((gVarJ.l() / 2) + gVarJ.k());
                } else {
                    iArr[1] = 0;
                }
                return iArr;
            default:
                int[] iArr2 = new int[2];
                if (abstractC1381n0.d()) {
                    iArr2[0] = c(view, i(abstractC1381n0));
                } else {
                    iArr2[0] = 0;
                }
                if (abstractC1381n0.e()) {
                    iArr2[1] = c(view, k(abstractC1381n0));
                } else {
                    iArr2[1] = 0;
                }
                return iArr2;
        }
    }

    public int d(AbstractC1381n0 abstractC1381n0, androidx.emoji2.text.g gVar, int i, int i2) {
        this.b.fling(0, 0, i, i2, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO, Integer.MIN_VALUE, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        int[] iArr = {this.b.getFinalX(), this.b.getFinalY()};
        int iV = abstractC1381n0.v();
        float f = 1.0f;
        if (iV != 0) {
            View view = null;
            int i3 = Integer.MIN_VALUE;
            int i4 = Integer.MAX_VALUE;
            View view2 = null;
            for (int i5 = 0; i5 < iV; i5++) {
                View viewU = abstractC1381n0.u(i5);
                int iK = AbstractC1381n0.K(viewU);
                if (iK != -1) {
                    if (iK < i4) {
                        view = viewU;
                        i4 = iK;
                    }
                    if (iK > i3) {
                        view2 = viewU;
                        i3 = iK;
                    }
                }
            }
            if (view != null && view2 != null) {
                int iMax = Math.max(gVar.b(view), gVar.b(view2)) - Math.min(gVar.e(view), gVar.e(view2));
                if (iMax != 0) {
                    f = (iMax * 1.0f) / ((i3 - i4) + 1);
                }
            }
        }
        if (f <= DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        return Math.round((Math.abs(iArr[0]) > Math.abs(iArr[1]) ? iArr[0] : iArr[1]) / f);
    }

    public View g(AbstractC1381n0 abstractC1381n0) {
        switch (this.d) {
            case 0:
                if (abstractC1381n0.e()) {
                    return e(abstractC1381n0, j(abstractC1381n0));
                }
                if (abstractC1381n0.d()) {
                    return e(abstractC1381n0, h(abstractC1381n0));
                }
                return null;
            default:
                if (abstractC1381n0.e()) {
                    return f(abstractC1381n0, k(abstractC1381n0));
                }
                if (abstractC1381n0.d()) {
                    return f(abstractC1381n0, i(abstractC1381n0));
                }
                return null;
        }
    }

    public androidx.emoji2.text.g h(AbstractC1381n0 abstractC1381n0) {
        Y y = this.f;
        if (y == null || ((AbstractC1381n0) y.b) != abstractC1381n0) {
            this.f = new Y(abstractC1381n0, 0);
        }
        return this.f;
    }

    public androidx.emoji2.text.g i(AbstractC1381n0 abstractC1381n0) {
        Y y = this.f;
        if (y == null || ((AbstractC1381n0) y.b) != abstractC1381n0) {
            this.f = new Y(abstractC1381n0, 0);
        }
        return this.f;
    }

    public androidx.emoji2.text.g j(AbstractC1381n0 abstractC1381n0) {
        Y y = this.e;
        if (y == null || ((AbstractC1381n0) y.b) != abstractC1381n0) {
            this.e = new Y(abstractC1381n0, 1);
        }
        return this.e;
    }

    public androidx.emoji2.text.g k(AbstractC1381n0 abstractC1381n0) {
        Y y = this.e;
        if (y == null || ((AbstractC1381n0) y.b) != abstractC1381n0) {
            this.e = new Y(abstractC1381n0, 1);
        }
        return this.e;
    }

    public final void l() {
        AbstractC1381n0 layoutManager;
        View viewG;
        RecyclerView recyclerView = this.a;
        if (recyclerView == null || (layoutManager = recyclerView.getLayoutManager()) == null || (viewG = g(layoutManager)) == null) {
            return;
        }
        int[] iArrB = b(layoutManager, viewG);
        int i = iArrB[0];
        if (i == 0 && iArrB[1] == 0) {
            return;
        }
        this.a.m0(i, iArrB[1], false);
    }
}
