package androidx.swiperefreshlayout.widget;

import android.animation.ValueAnimator;
import android.view.View;

/* loaded from: classes.dex */
public final class b implements ValueAnimator.AnimatorUpdateListener {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;

    public b(com.facebook.appevents.k kVar, View[] viewArr) {
        this.b = kVar;
        this.c = viewArr;
    }

    public static b a(View... viewArr) {
        return new b(new com.facebook.appevents.k(19), viewArr);
    }

    @Override // android.animation.ValueAnimator.AnimatorUpdateListener
    public final void onAnimationUpdate(ValueAnimator valueAnimator) {
        switch (this.a) {
            case 0:
                float fFloatValue = ((Float) valueAnimator.getAnimatedValue()).floatValue();
                e eVar = (e) this.c;
                d dVar = (d) this.b;
                e.d(fFloatValue, dVar);
                eVar.a(fFloatValue, dVar, false);
                eVar.invalidateSelf();
                break;
            default:
                for (View view : (View[]) this.c) {
                    switch (((com.facebook.appevents.k) this.b).a) {
                        case 18:
                            view.setTranslationX(((Float) valueAnimator.getAnimatedValue()).floatValue());
                            break;
                        case 19:
                            view.setTranslationY(((Float) valueAnimator.getAnimatedValue()).floatValue());
                            break;
                        case 20:
                            Float f = (Float) valueAnimator.getAnimatedValue();
                            view.setScaleX(f.floatValue());
                            view.setScaleY(f.floatValue());
                            break;
                        default:
                            view.setAlpha(((Float) valueAnimator.getAnimatedValue()).floatValue());
                            break;
                    }
                }
                break;
        }
    }

    public b(e eVar, d dVar) {
        this.c = eVar;
        this.b = dVar;
    }
}
