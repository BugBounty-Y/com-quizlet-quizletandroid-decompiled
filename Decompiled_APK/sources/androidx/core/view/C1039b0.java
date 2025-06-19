package androidx.core.view;

import android.animation.ValueAnimator;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.view.ViewGroup;
import com.braze.ui.inappmessage.listeners.SwipeDismissTouchListener;
import com.google.android.material.appbar.AppBarLayout;
import java.util.Iterator;

/* renamed from: androidx.core.view.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1039b0 implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ C1039b0(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                ((View) ((androidx.appcompat.app.T) ((androidx.appcompat.app.Q) obj2).a).d.getParent()).invalidate();
                return;
            case 1:
                ((SwipeDismissTouchListener) obj2).lambda$performDismiss$0((ViewGroup.LayoutParams) obj, valueAnimator);
                return;
            default:
                int i = AppBarLayout.z;
                AppBarLayout appBarLayout = (AppBarLayout) obj2;
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                ((com.google.android.material.shape.g) obj).l(fFloatValue);
                Drawable drawable = appBarLayout.v;
                if (drawable instanceof com.google.android.material.shape.g) {
                    ((com.google.android.material.shape.g) drawable).l(fFloatValue);
                }
                Iterator it2 = appBarLayout.r.iterator();
                if (it2.hasNext()) {
                    throw android.support.v4.media.session.a.d(it2);
                }
                return;
        }
    }
}
