package androidx.swiperefreshlayout.widget;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.Transformation;
import com.quizlet.partskit.widgets.QProgressBar;

/* loaded from: classes.dex */
public final class h extends Animation {
    public final /* synthetic */ int a = 0;
    public final int b;
    public final int c;
    public final /* synthetic */ View d;

    public h(QProgressBar qProgressBar, int i, int i2) {
        this.d = qProgressBar;
        this.b = i;
        this.c = i2;
    }

    @Override // android.view.animation.Animation
    public final void applyTransformation(float f, Transformation transformation) {
        switch (this.a) {
            case 0:
                ((SwipeRefreshLayout) this.d).z.setAlpha((int) (((this.c - r0) * f) + this.b));
                break;
            default:
                super.applyTransformation(f, transformation);
                ((QProgressBar) this.d).setUnscaledProgress((int) (((this.c - r5) * f) + this.b));
                break;
        }
    }

    public h(SwipeRefreshLayout swipeRefreshLayout, int i, int i2) {
        this.d = swipeRefreshLayout;
        this.b = i;
        this.c = i2;
    }
}
