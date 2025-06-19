package androidx.recyclerview.widget;

import android.content.Context;
import android.graphics.PointF;
import android.util.DisplayMetrics;
import android.view.View;
import android.view.animation.DecelerateInterpolator;
import com.google.android.material.carousel.CarouselLayoutManager;
import com.quizlet.diagrams.layoutmanager.FlashCardsLayoutManager;

/* loaded from: classes.dex */
public final class Z extends S {
    public final /* synthetic */ int q;
    public final /* synthetic */ Object r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ Z(int i, Context context, Object obj) {
        super(context);
        this.q = i;
        this.r = obj;
    }

    @Override // androidx.recyclerview.widget.S
    public int b(View view, int i) {
        switch (this.q) {
            case 2:
                ((CarouselLayoutManager) this.r).getClass();
                return 0;
            default:
                return super.b(view, i);
        }
    }

    @Override // androidx.recyclerview.widget.S
    public int c(View view, int i) {
        switch (this.q) {
            case 2:
                ((CarouselLayoutManager) this.r).getClass();
                return 0;
            default:
                return super.c(view, i);
        }
    }

    @Override // androidx.recyclerview.widget.S
    public float d(DisplayMetrics displayMetrics) {
        switch (this.q) {
            case 0:
                return 100.0f / displayMetrics.densityDpi;
            case 1:
                return 100.0f / displayMetrics.densityDpi;
            default:
                return super.d(displayMetrics);
        }
    }

    @Override // androidx.recyclerview.widget.S
    public int e(int i) {
        switch (this.q) {
            case 0:
                return Math.min(100, super.e(i));
            default:
                return super.e(i);
        }
    }

    @Override // androidx.recyclerview.widget.S
    public PointF f(int i) {
        switch (this.q) {
            case 2:
                ((CarouselLayoutManager) this.r).getClass();
                return null;
            case 3:
                return ((FlashCardsLayoutManager) this.r).a(i);
            default:
                return super.f(i);
        }
    }

    @Override // androidx.recyclerview.widget.S
    public int g() {
        switch (this.q) {
            case 3:
                return -1;
            default:
                return super.g();
        }
    }

    @Override // androidx.recyclerview.widget.S
    public int h() {
        switch (this.q) {
            case 3:
                return -1;
            default:
                return super.h();
        }
    }

    @Override // androidx.recyclerview.widget.S
    public void j(View view, z0 z0Var) {
        switch (this.q) {
            case 0:
                T t = (T) this.r;
                int[] iArrB = t.b(t.a.getLayoutManager(), view);
                int i = iArrB[0];
                int i2 = iArrB[1];
                int iCeil = (int) Math.ceil(e(Math.max(Math.abs(i), Math.abs(i2))) / 0.3356d);
                if (iCeil > 0) {
                    DecelerateInterpolator decelerateInterpolator = this.j;
                    z0Var.a = i;
                    z0Var.b = i2;
                    z0Var.c = iCeil;
                    z0Var.e = decelerateInterpolator;
                    z0Var.f = true;
                    break;
                }
                break;
            case 1:
                T t2 = (T) this.r;
                RecyclerView recyclerView = t2.a;
                if (recyclerView != null) {
                    int[] iArrB2 = t2.b(recyclerView.getLayoutManager(), view);
                    int i3 = iArrB2[0];
                    int i4 = iArrB2[1];
                    int iCeil2 = (int) Math.ceil(e(Math.max(Math.abs(i3), Math.abs(i4))) / 0.3356d);
                    if (iCeil2 > 0) {
                        DecelerateInterpolator decelerateInterpolator2 = this.j;
                        z0Var.a = i3;
                        z0Var.b = i4;
                        z0Var.c = iCeil2;
                        z0Var.e = decelerateInterpolator2;
                        z0Var.f = true;
                        break;
                    }
                }
                break;
            default:
                super.j(view, z0Var);
                break;
        }
    }
}
