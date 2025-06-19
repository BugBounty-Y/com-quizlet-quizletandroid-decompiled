package androidx.fragment.app;

import android.animation.Animator;
import android.animation.AnimatorInflater;
import android.content.Context;
import android.content.res.Resources;
import android.view.ViewGroup;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3135e7;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.fragment.app.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1129e extends AbstractC1139j {
    public final boolean b;
    public boolean c;
    public J d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1129e(H0 operation, boolean z) {
        super(operation);
        Intrinsics.checkNotNullParameter(operation, "operation");
        this.b = z;
    }

    public final J b(Context context) throws Resources.NotFoundException {
        Animation animationLoadAnimation;
        J j;
        Intrinsics.checkNotNullParameter(context, "context");
        if (this.c) {
            return this.d;
        }
        H0 h0 = this.a;
        Fragment fragment = h0.c;
        boolean z = h0.a == J0.b;
        int nextTransition = fragment.getNextTransition();
        int popEnterAnim = this.b ? z ? fragment.getPopEnterAnim() : fragment.getPopExitAnim() : z ? fragment.getEnterAnim() : fragment.getExitAnim();
        fragment.setAnimations(0, 0, 0, 0);
        ViewGroup viewGroup = fragment.mContainer;
        J j2 = null;
        if (viewGroup != null && viewGroup.getTag(R.id.visible_removing_fragment_view_tag) != null) {
            fragment.mContainer.setTag(R.id.visible_removing_fragment_view_tag, null);
        }
        ViewGroup viewGroup2 = fragment.mContainer;
        if (viewGroup2 == null || viewGroup2.getLayoutTransition() == null) {
            Animation animationOnCreateAnimation = fragment.onCreateAnimation(nextTransition, z, popEnterAnim);
            if (animationOnCreateAnimation != null) {
                j2 = new J(animationOnCreateAnimation);
            } else {
                Animator animatorOnCreateAnimator = fragment.onCreateAnimator(nextTransition, z, popEnterAnim);
                if (animatorOnCreateAnimator != null) {
                    j2 = new J(animatorOnCreateAnimator);
                } else {
                    if (popEnterAnim == 0 && nextTransition != 0) {
                        popEnterAnim = nextTransition != 4097 ? nextTransition != 8194 ? nextTransition != 8197 ? nextTransition != 4099 ? nextTransition != 4100 ? -1 : z ? AbstractC3135e7.c(context, android.R.attr.activityOpenEnterAnimation) : AbstractC3135e7.c(context, android.R.attr.activityOpenExitAnimation) : z ? R.animator.fragment_fade_enter : R.animator.fragment_fade_exit : z ? AbstractC3135e7.c(context, android.R.attr.activityCloseEnterAnimation) : AbstractC3135e7.c(context, android.R.attr.activityCloseExitAnimation) : z ? R.animator.fragment_close_enter : R.animator.fragment_close_exit : z ? R.animator.fragment_open_enter : R.animator.fragment_open_exit;
                    }
                    if (popEnterAnim != 0) {
                        boolean zEquals = "anim".equals(context.getResources().getResourceTypeName(popEnterAnim));
                        if (zEquals) {
                            try {
                                animationLoadAnimation = AnimationUtils.loadAnimation(context, popEnterAnim);
                            } catch (Resources.NotFoundException e) {
                                throw e;
                            } catch (RuntimeException unused) {
                            }
                            if (animationLoadAnimation != null) {
                                j = new J(animationLoadAnimation);
                                j2 = j;
                            }
                        } else {
                            try {
                                Animator animatorLoadAnimator = AnimatorInflater.loadAnimator(context, popEnterAnim);
                                if (animatorLoadAnimator != null) {
                                    j = new J(animatorLoadAnimator);
                                    j2 = j;
                                }
                            } catch (RuntimeException e2) {
                                if (zEquals) {
                                    throw e2;
                                }
                                Animation animationLoadAnimation2 = AnimationUtils.loadAnimation(context, popEnterAnim);
                                if (animationLoadAnimation2 != null) {
                                    j2 = new J(animationLoadAnimation2);
                                }
                            }
                        }
                    }
                }
            }
        }
        this.d = j2;
        this.c = true;
        return j2;
    }
}
