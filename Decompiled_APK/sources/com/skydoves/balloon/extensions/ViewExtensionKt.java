package com.skydoves.balloon.extensions;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.app.Activity;
import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.view.View;
import android.view.ViewAnimationUtils;
import com.facebook.appevents.internal.a;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class ViewExtensionKt {
    public static final /* synthetic */ void circularRevealed(View view, long j) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setVisibility(4);
        view.post(new a(view, j));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final void circularRevealed$lambda$1(View view, long j) {
        if (view.isAttachedToWindow()) {
            view.setVisibility(0);
            Animator animatorCreateCircularReveal = ViewAnimationUtils.createCircularReveal(view, (view.getRight() + view.getLeft()) / 2, (view.getBottom() + view.getTop()) / 2, DefinitionKt.NO_Float_VALUE, Math.max(view.getWidth(), view.getHeight()));
            animatorCreateCircularReveal.setDuration(j);
            animatorCreateCircularReveal.start();
        }
    }

    public static final /* synthetic */ void circularUnRevealed(final View view, final long j, final Function0<Unit> doAfterFinish) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Intrinsics.checkNotNullParameter(doAfterFinish, "doAfterFinish");
        view.post(new Runnable() { // from class: com.skydoves.balloon.extensions.ViewExtensionKt.circularUnRevealed.1
            @Override // java.lang.Runnable
            public final void run() {
                if (view.isAttachedToWindow()) {
                    View view2 = view;
                    Animator animatorCreateCircularReveal = ViewAnimationUtils.createCircularReveal(view2, (view.getRight() + view2.getLeft()) / 2, (view.getBottom() + view.getTop()) / 2, Math.max(view.getWidth(), view.getHeight()), DefinitionKt.NO_Float_VALUE);
                    animatorCreateCircularReveal.setDuration(j);
                    animatorCreateCircularReveal.start();
                    final Function0<Unit> function0 = doAfterFinish;
                    animatorCreateCircularReveal.addListener(new AnimatorListenerAdapter() { // from class: com.skydoves.balloon.extensions.ViewExtensionKt.circularUnRevealed.1.2
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            Intrinsics.checkNotNullParameter(animation, "animation");
                            super.onAnimationEnd(animation);
                            function0.invoke();
                        }
                    });
                }
            }
        });
    }

    public static final /* synthetic */ int getStatusBarHeight(View view, boolean z) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        Rect rect = new Rect();
        Context context = view.getContext();
        if (!(context instanceof Activity) || !z) {
            return 0;
        }
        ((Activity) context).getWindow().getDecorView().getWindowVisibleDisplayFrame(rect);
        return rect.top;
    }

    public static final /* synthetic */ Point getViewPointOnScreen(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        int[] iArr = {0, 0};
        view.getLocationOnScreen(iArr);
        return new Point(iArr[0], iArr[1]);
    }

    public static final /* synthetic */ void visible(View view, boolean z) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setVisibility(z ? 0 : 8);
    }
}
