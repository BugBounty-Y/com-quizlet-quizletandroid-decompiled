package androidx.recyclerview.widget;

import android.annotation.SuppressLint;
import android.content.Context;
import android.graphics.PointF;
import android.util.DisplayMetrics;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.LinearInterpolator;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public class S {
    public int a = -1;
    public RecyclerView b;
    public AbstractC1381n0 c;
    public boolean d;
    public boolean e;
    public View f;
    public final z0 g;
    public boolean h;
    public final LinearInterpolator i;
    public final DecelerateInterpolator j;
    public PointF k;
    public final DisplayMetrics l;
    public boolean m;
    public float n;
    public int o;
    public int p;

    @SuppressLint({"UnknownNullness"})
    public S(Context context) {
        z0 z0Var = new z0();
        z0Var.d = -1;
        z0Var.f = false;
        z0Var.g = 0;
        z0Var.a = 0;
        z0Var.b = 0;
        z0Var.c = Integer.MIN_VALUE;
        z0Var.e = null;
        this.g = z0Var;
        this.i = new LinearInterpolator();
        this.j = new DecelerateInterpolator();
        this.m = false;
        this.o = 0;
        this.p = 0;
        this.l = context.getResources().getDisplayMetrics();
    }

    public int a(int i, int i2, int i3, int i4, int i5) {
        if (i5 == -1) {
            return i3 - i;
        }
        if (i5 != 0) {
            if (i5 == 1) {
                return i4 - i2;
            }
            throw new IllegalArgumentException("snap preference should be one of the constants defined in SmoothScroller, starting with SNAP_");
        }
        int i6 = i3 - i;
        if (i6 > 0) {
            return i6;
        }
        int i7 = i4 - i2;
        if (i7 < 0) {
            return i7;
        }
        return 0;
    }

    public int b(View view, int i) {
        AbstractC1381n0 abstractC1381n0 = this.c;
        if (abstractC1381n0 == null || !abstractC1381n0.d()) {
            return 0;
        }
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        return a(AbstractC1381n0.A(view) - ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin, AbstractC1381n0.D(view) + ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin, abstractC1381n0.H(), abstractC1381n0.n - abstractC1381n0.I(), i);
    }

    public int c(View view, int i) {
        AbstractC1381n0 abstractC1381n0 = this.c;
        if (abstractC1381n0 == null || !abstractC1381n0.e()) {
            return 0;
        }
        C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
        return a(AbstractC1381n0.E(view) - ((ViewGroup.MarginLayoutParams) c1383o0).topMargin, AbstractC1381n0.y(view) + ((ViewGroup.MarginLayoutParams) c1383o0).bottomMargin, abstractC1381n0.J(), abstractC1381n0.o - abstractC1381n0.G(), i);
    }

    public float d(DisplayMetrics displayMetrics) {
        return 25.0f / displayMetrics.densityDpi;
    }

    public int e(int i) {
        float fAbs = Math.abs(i);
        if (!this.m) {
            this.n = d(this.l);
            this.m = true;
        }
        return (int) Math.ceil(fAbs * this.n);
    }

    public PointF f(int i) {
        Object obj = this.c;
        if (obj instanceof A0) {
            return ((A0) obj).a(i);
        }
        Log.w("RecyclerView", "You should override computeScrollVectorForPosition when the LayoutManager does not implement " + A0.class.getCanonicalName());
        return null;
    }

    public int g() {
        PointF pointF = this.k;
        if (pointF == null) {
            return 0;
        }
        float f = pointF.x;
        if (f == DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        return f > DefinitionKt.NO_Float_VALUE ? 1 : -1;
    }

    public int h() {
        PointF pointF = this.k;
        if (pointF == null) {
            return 0;
        }
        float f = pointF.y;
        if (f == DefinitionKt.NO_Float_VALUE) {
            return 0;
        }
        return f > DefinitionKt.NO_Float_VALUE ? 1 : -1;
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00f8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(int r9, int r10) {
        /*
            Method dump skipped, instructions count: 277
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.recyclerview.widget.S.i(int, int):void");
    }

    public void j(View view, z0 z0Var) {
        int iB = b(view, g());
        int iC = c(view, h());
        int iCeil = (int) Math.ceil(e((int) Math.sqrt((iC * iC) + (iB * iB))) / 0.3356d);
        if (iCeil > 0) {
            DecelerateInterpolator decelerateInterpolator = this.j;
            z0Var.a = -iB;
            z0Var.b = -iC;
            z0Var.c = iCeil;
            z0Var.e = decelerateInterpolator;
            z0Var.f = true;
        }
    }

    public final void k() {
        if (this.e) {
            this.e = false;
            this.p = 0;
            this.o = 0;
            this.k = null;
            this.b.r1.a = -1;
            this.f = null;
            this.a = -1;
            this.d = false;
            AbstractC1381n0 abstractC1381n0 = this.c;
            if (abstractC1381n0.e == this) {
                abstractC1381n0.e = null;
            }
            this.c = null;
            this.b = null;
        }
    }
}
