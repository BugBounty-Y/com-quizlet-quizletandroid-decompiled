package androidx.core.view;

import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.PathInterpolator;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

/* loaded from: classes.dex */
public final class i0 extends l0 {
    public static final PathInterpolator e = new PathInterpolator(DefinitionKt.NO_Float_VALUE, 1.1f, DefinitionKt.NO_Float_VALUE, 1.0f);
    public static final androidx.interpolator.view.animation.a f = new androidx.interpolator.view.animation.a(0);
    public static final DecelerateInterpolator g = new DecelerateInterpolator(1.5f);
    public static final AccelerateInterpolator h = new AccelerateInterpolator(1.5f);

    public static void e(View view, m0 m0Var) {
        AbstractC1047f0 abstractC1047f0J = j(view);
        if (abstractC1047f0J != null) {
            abstractC1047f0J.d(m0Var);
            if (abstractC1047f0J.a == 0) {
                return;
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                e(viewGroup.getChildAt(i), m0Var);
            }
        }
    }

    public static void f(View view, m0 m0Var, D0 d0, boolean z) {
        AbstractC1047f0 abstractC1047f0J = j(view);
        if (abstractC1047f0J != null) {
            abstractC1047f0J.b = d0;
            if (!z) {
                abstractC1047f0J.e();
                z = abstractC1047f0J.a == 0;
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                f(viewGroup.getChildAt(i), m0Var, d0, z);
            }
        }
    }

    public static void g(View view, D0 d0, List list) {
        AbstractC1047f0 abstractC1047f0J = j(view);
        if (abstractC1047f0J != null) {
            d0 = abstractC1047f0J.f(d0, list);
            if (abstractC1047f0J.a == 0) {
                return;
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                g(viewGroup.getChildAt(i), d0, list);
            }
        }
    }

    public static void h(View view, m0 m0Var, androidx.work.impl.model.e eVar) {
        AbstractC1047f0 abstractC1047f0J = j(view);
        if (abstractC1047f0J != null) {
            abstractC1047f0J.g(eVar);
            if (abstractC1047f0J.a == 0) {
                return;
            }
        }
        if (view instanceof ViewGroup) {
            ViewGroup viewGroup = (ViewGroup) view;
            for (int i = 0; i < viewGroup.getChildCount(); i++) {
                h(viewGroup.getChildAt(i), m0Var, eVar);
            }
        }
    }

    public static WindowInsets i(View view, WindowInsets windowInsets) {
        return view.getTag(R.id.tag_on_apply_window_listener) != null ? windowInsets : view.onApplyWindowInsets(windowInsets);
    }

    public static AbstractC1047f0 j(View view) {
        Object tag = view.getTag(R.id.tag_window_insets_animation_callback);
        if (tag instanceof ViewOnApplyWindowInsetsListenerC1051h0) {
            return ((ViewOnApplyWindowInsetsListenerC1051h0) tag).a;
        }
        return null;
    }
}
