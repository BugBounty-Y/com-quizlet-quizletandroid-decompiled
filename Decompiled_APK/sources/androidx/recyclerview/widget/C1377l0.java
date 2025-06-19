package androidx.recyclerview.widget;

import android.view.View;
import android.view.ViewGroup;

/* renamed from: androidx.recyclerview.widget.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1377l0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC1381n0 b;

    public /* synthetic */ C1377l0(AbstractC1381n0 abstractC1381n0, int i) {
        this.a = i;
        this.b = abstractC1381n0;
    }

    public final int a(View view) {
        switch (this.a) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                this.b.getClass();
                return AbstractC1381n0.D(view) + ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                this.b.getClass();
                return AbstractC1381n0.y(view) + ((ViewGroup.MarginLayoutParams) c1383o02).bottomMargin;
        }
    }

    public final int b(View view) {
        switch (this.a) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                this.b.getClass();
                return AbstractC1381n0.A(view) - ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                this.b.getClass();
                return AbstractC1381n0.E(view) - ((ViewGroup.MarginLayoutParams) c1383o02).topMargin;
        }
    }

    public final int c() {
        switch (this.a) {
            case 0:
                AbstractC1381n0 abstractC1381n0 = this.b;
                return abstractC1381n0.n - abstractC1381n0.I();
            default:
                AbstractC1381n0 abstractC1381n02 = this.b;
                return abstractC1381n02.o - abstractC1381n02.G();
        }
    }

    public final int d() {
        switch (this.a) {
            case 0:
                return this.b.H();
            default:
                return this.b.J();
        }
    }
}
