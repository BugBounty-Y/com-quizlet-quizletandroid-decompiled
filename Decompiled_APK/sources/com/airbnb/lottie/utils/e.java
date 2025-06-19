package com.airbnb.lottie.utils;

import android.animation.Animator;
import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.graphics.PointF;
import android.view.Choreographer;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Iterator;
import java.util.concurrent.CopyOnWriteArraySet;

/* loaded from: classes.dex */
public final class e extends ValueAnimator implements Choreographer.FrameCallback {
    public com.airbnb.lottie.h l;
    public final CopyOnWriteArraySet a = new CopyOnWriteArraySet();
    public final CopyOnWriteArraySet b = new CopyOnWriteArraySet();
    public final CopyOnWriteArraySet c = new CopyOnWriteArraySet();
    public float d = 1.0f;
    public boolean e = false;
    public long f = 0;
    public float g = DefinitionKt.NO_Float_VALUE;
    public float h = DefinitionKt.NO_Float_VALUE;
    public int i = 0;
    public float j = -2.1474836E9f;
    public float k = 2.1474836E9f;
    public boolean m = false;
    public boolean n = false;

    @Override // android.animation.Animator
    public final void addListener(Animator.AnimatorListener animatorListener) {
        this.b.add(animatorListener);
    }

    @Override // android.animation.Animator
    public final void addPauseListener(Animator.AnimatorPauseListener animatorPauseListener) {
        this.c.add(animatorPauseListener);
    }

    @Override // android.animation.ValueAnimator
    public final void addUpdateListener(ValueAnimator.AnimatorUpdateListener animatorUpdateListener) {
        this.a.add(animatorUpdateListener);
    }

    public final float b() {
        com.airbnb.lottie.h hVar = this.l;
        if (hVar == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = this.h;
        float f2 = hVar.l;
        return (f - f2) / (hVar.m - f2);
    }

    public final float c() {
        com.airbnb.lottie.h hVar = this.l;
        if (hVar == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = this.k;
        return f == 2.1474836E9f ? hVar.m : f;
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final void cancel() {
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            ((Animator.AnimatorListener) it2.next()).onAnimationCancel(this);
        }
        f(e());
        h(true);
    }

    public final float d() {
        com.airbnb.lottie.h hVar = this.l;
        if (hVar == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = this.j;
        return f == -2.1474836E9f ? hVar.l : f;
    }

    @Override // android.view.Choreographer.FrameCallback
    public final void doFrame(long j) {
        boolean z = false;
        if (this.m) {
            h(false);
            Choreographer.getInstance().postFrameCallback(this);
        }
        com.airbnb.lottie.h hVar = this.l;
        if (hVar == null || !this.m) {
            return;
        }
        float fAbs = (this.f != 0 ? j - r2 : 0L) / ((1.0E9f / hVar.n) / Math.abs(this.d));
        float f = this.g;
        if (e()) {
            fAbs = -fAbs;
        }
        float f2 = f + fAbs;
        float fD = d();
        float fC = c();
        PointF pointF = g.a;
        if (f2 >= fD && f2 <= fC) {
            z = true;
        }
        float f3 = this.g;
        float fB = g.b(f2, d(), c());
        this.g = fB;
        if (this.n) {
            fB = (float) Math.floor(fB);
        }
        this.h = fB;
        this.f = j;
        if (z) {
            if (!this.n || this.g != f3) {
                g();
            }
        } else if (getRepeatCount() == -1 || this.i < getRepeatCount()) {
            if (getRepeatMode() == 2) {
                this.e = !this.e;
                this.d = -this.d;
            } else {
                float fC2 = e() ? c() : d();
                this.g = fC2;
                this.h = fC2;
            }
            this.f = j;
            if (!this.n || this.g != f3) {
                g();
            }
            Iterator it2 = this.b.iterator();
            while (it2.hasNext()) {
                ((Animator.AnimatorListener) it2.next()).onAnimationRepeat(this);
            }
            this.i++;
        } else {
            float fD2 = this.d < DefinitionKt.NO_Float_VALUE ? d() : c();
            this.g = fD2;
            this.h = fD2;
            h(true);
            if (!this.n || this.g != f3) {
                g();
            }
            f(e());
        }
        if (this.l == null) {
            return;
        }
        float f4 = this.h;
        if (f4 < this.j || f4 > this.k) {
            throw new IllegalStateException(String.format("Frame must be [%f,%f]. It is %f", Float.valueOf(this.j), Float.valueOf(this.k), Float.valueOf(this.h)));
        }
    }

    public final boolean e() {
        return this.d < DefinitionKt.NO_Float_VALUE;
    }

    public final void f(boolean z) {
        Iterator it2 = this.b.iterator();
        while (it2.hasNext()) {
            ((Animator.AnimatorListener) it2.next()).onAnimationEnd(this, z);
        }
    }

    public final void g() {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            ((ValueAnimator.AnimatorUpdateListener) it2.next()).onAnimationUpdate(this);
        }
    }

    @Override // android.animation.ValueAnimator
    public final float getAnimatedFraction() {
        float fD;
        float fC;
        float fD2;
        if (this.l == null) {
            return DefinitionKt.NO_Float_VALUE;
        }
        if (e()) {
            fD = c() - this.h;
            fC = c();
            fD2 = d();
        } else {
            fD = this.h - d();
            fC = c();
            fD2 = d();
        }
        return fD / (fC - fD2);
    }

    @Override // android.animation.ValueAnimator
    public final Object getAnimatedValue() {
        return Float.valueOf(b());
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final long getDuration() {
        com.airbnb.lottie.h hVar = this.l;
        if (hVar == null) {
            return 0L;
        }
        return (long) hVar.b();
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final long getStartDelay() {
        throw new UnsupportedOperationException("LottieAnimator does not support getStartDelay.");
    }

    public final void h(boolean z) {
        Choreographer.getInstance().removeFrameCallback(this);
        if (z) {
            this.m = false;
        }
    }

    public final void i(float f) {
        if (this.g == f) {
            return;
        }
        float fB = g.b(f, d(), c());
        this.g = fB;
        if (this.n) {
            fB = (float) Math.floor(fB);
        }
        this.h = fB;
        this.f = 0L;
        g();
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final boolean isRunning() {
        return this.m;
    }

    public final void k(float f, float f2) {
        if (f > f2) {
            throw new IllegalArgumentException("minFrame (" + f + ") must be <= maxFrame (" + f2 + ")");
        }
        com.airbnb.lottie.h hVar = this.l;
        float f3 = hVar == null ? -3.4028235E38f : hVar.l;
        float f4 = hVar == null ? Float.MAX_VALUE : hVar.m;
        float fB = g.b(f, f3, f4);
        float fB2 = g.b(f2, f3, f4);
        if (fB == this.j && fB2 == this.k) {
            return;
        }
        this.j = fB;
        this.k = fB2;
        i((int) g.b(this.h, fB, fB2));
    }

    @Override // android.animation.Animator
    public final void removeAllListeners() {
        this.b.clear();
    }

    @Override // android.animation.ValueAnimator
    public final void removeAllUpdateListeners() {
        this.a.clear();
    }

    @Override // android.animation.Animator
    public final void removeListener(Animator.AnimatorListener animatorListener) {
        this.b.remove(animatorListener);
    }

    @Override // android.animation.Animator
    public final void removePauseListener(Animator.AnimatorPauseListener animatorPauseListener) {
        this.c.remove(animatorPauseListener);
    }

    @Override // android.animation.ValueAnimator
    public final void removeUpdateListener(ValueAnimator.AnimatorUpdateListener animatorUpdateListener) {
        this.a.remove(animatorUpdateListener);
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final /* bridge */ /* synthetic */ Animator setDuration(long j) {
        setDuration(j);
        throw null;
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final void setInterpolator(TimeInterpolator timeInterpolator) {
        throw new UnsupportedOperationException("LottieAnimator does not support setInterpolator.");
    }

    @Override // android.animation.ValueAnimator
    public final void setRepeatMode(int i) {
        super.setRepeatMode(i);
        if (i == 2 || !this.e) {
            return;
        }
        this.e = false;
        this.d = -this.d;
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final void setStartDelay(long j) {
        throw new UnsupportedOperationException("LottieAnimator does not support setStartDelay.");
    }

    @Override // android.animation.ValueAnimator, android.animation.Animator
    public final ValueAnimator setDuration(long j) {
        throw new UnsupportedOperationException("LottieAnimator does not support setDuration.");
    }
}
