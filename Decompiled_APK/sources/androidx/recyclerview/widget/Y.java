package androidx.recyclerview.widget;

import android.graphics.Rect;
import android.view.View;
import android.view.ViewGroup;

/* loaded from: classes.dex */
public final class Y extends androidx.emoji2.text.g {
    public final /* synthetic */ int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Y(AbstractC1381n0 abstractC1381n0, int i) {
        super(abstractC1381n0);
        this.d = i;
    }

    @Override // androidx.emoji2.text.g
    public final int b(View view) {
        switch (this.d) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.D(view) + ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.y(view) + ((ViewGroup.MarginLayoutParams) c1383o02).bottomMargin;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int c(View view) {
        switch (this.d) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.C(view) + ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin + ((ViewGroup.MarginLayoutParams) c1383o0).rightMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.B(view) + ((ViewGroup.MarginLayoutParams) c1383o02).topMargin + ((ViewGroup.MarginLayoutParams) c1383o02).bottomMargin;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int d(View view) {
        switch (this.d) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.B(view) + ((ViewGroup.MarginLayoutParams) c1383o0).topMargin + ((ViewGroup.MarginLayoutParams) c1383o0).bottomMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.C(view) + ((ViewGroup.MarginLayoutParams) c1383o02).leftMargin + ((ViewGroup.MarginLayoutParams) c1383o02).rightMargin;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int e(View view) {
        switch (this.d) {
            case 0:
                C1383o0 c1383o0 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.A(view) - ((ViewGroup.MarginLayoutParams) c1383o0).leftMargin;
            default:
                C1383o0 c1383o02 = (C1383o0) view.getLayoutParams();
                ((AbstractC1381n0) this.b).getClass();
                return AbstractC1381n0.E(view) - ((ViewGroup.MarginLayoutParams) c1383o02).topMargin;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int f() {
        switch (this.d) {
            case 0:
                return ((AbstractC1381n0) this.b).n;
            default:
                return ((AbstractC1381n0) this.b).o;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int g() {
        switch (this.d) {
            case 0:
                AbstractC1381n0 abstractC1381n0 = (AbstractC1381n0) this.b;
                return abstractC1381n0.n - abstractC1381n0.I();
            default:
                AbstractC1381n0 abstractC1381n02 = (AbstractC1381n0) this.b;
                return abstractC1381n02.o - abstractC1381n02.G();
        }
    }

    @Override // androidx.emoji2.text.g
    public final int h() {
        switch (this.d) {
            case 0:
                return ((AbstractC1381n0) this.b).I();
            default:
                return ((AbstractC1381n0) this.b).G();
        }
    }

    @Override // androidx.emoji2.text.g
    public final int i() {
        switch (this.d) {
            case 0:
                return ((AbstractC1381n0) this.b).l;
            default:
                return ((AbstractC1381n0) this.b).m;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int j() {
        switch (this.d) {
            case 0:
                return ((AbstractC1381n0) this.b).m;
            default:
                return ((AbstractC1381n0) this.b).l;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int k() {
        switch (this.d) {
            case 0:
                return ((AbstractC1381n0) this.b).H();
            default:
                return ((AbstractC1381n0) this.b).J();
        }
    }

    @Override // androidx.emoji2.text.g
    public final int l() {
        switch (this.d) {
            case 0:
                AbstractC1381n0 abstractC1381n0 = (AbstractC1381n0) this.b;
                return (abstractC1381n0.n - abstractC1381n0.H()) - abstractC1381n0.I();
            default:
                AbstractC1381n0 abstractC1381n02 = (AbstractC1381n0) this.b;
                return (abstractC1381n02.o - abstractC1381n02.J()) - abstractC1381n02.G();
        }
    }

    @Override // androidx.emoji2.text.g
    public final int m(View view) {
        switch (this.d) {
            case 0:
                AbstractC1381n0 abstractC1381n0 = (AbstractC1381n0) this.b;
                Rect rect = (Rect) this.c;
                abstractC1381n0.N(rect, view);
                return rect.right;
            default:
                AbstractC1381n0 abstractC1381n02 = (AbstractC1381n0) this.b;
                Rect rect2 = (Rect) this.c;
                abstractC1381n02.N(rect2, view);
                return rect2.bottom;
        }
    }

    @Override // androidx.emoji2.text.g
    public final int n(View view) {
        switch (this.d) {
            case 0:
                AbstractC1381n0 abstractC1381n0 = (AbstractC1381n0) this.b;
                Rect rect = (Rect) this.c;
                abstractC1381n0.N(rect, view);
                return rect.left;
            default:
                AbstractC1381n0 abstractC1381n02 = (AbstractC1381n0) this.b;
                Rect rect2 = (Rect) this.c;
                abstractC1381n02.N(rect2, view);
                return rect2.top;
        }
    }

    @Override // androidx.emoji2.text.g
    public final void o(int i) {
        switch (this.d) {
            case 0:
                ((AbstractC1381n0) this.b).S(i);
                break;
            default:
                ((AbstractC1381n0) this.b).T(i);
                break;
        }
    }
}
