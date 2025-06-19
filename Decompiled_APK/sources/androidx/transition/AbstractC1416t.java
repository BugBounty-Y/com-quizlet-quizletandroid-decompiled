package androidx.transition;

import android.animation.Animator;
import android.animation.AnimatorSet;

/* renamed from: androidx.transition.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1416t {
    public static long a(Animator animator) {
        return animator.getTotalDuration();
    }

    public static void b(Animator animator, long j) {
        ((AnimatorSet) animator).setCurrentPlayTime(j);
    }
}
