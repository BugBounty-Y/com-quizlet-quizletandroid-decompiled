package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.StateListAnimator;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.util.Property;
import android.view.View;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class s extends q {
    public StateListAnimator N;

    @Override // com.google.android.material.floatingactionbutton.q
    public final float e() {
        return this.v.getElevation();
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void f(Rect rect) {
        if (((FloatingActionButton) this.w.a).k) {
            super.f(rect);
            return;
        }
        if (this.f) {
            FloatingActionButton floatingActionButton = this.v;
            int sizeDimension = floatingActionButton.getSizeDimension();
            int i = this.k;
            if (sizeDimension < i) {
                int sizeDimension2 = (i - floatingActionButton.getSizeDimension()) / 2;
                rect.set(sizeDimension2, sizeDimension2, sizeDimension2, sizeDimension2);
                return;
            }
        }
        rect.set(0, 0, 0, 0);
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void g(ColorStateList colorStateList, PorterDuff.Mode mode, ColorStateList colorStateList2, int i) {
        Drawable layerDrawable;
        com.google.android.material.shape.j jVar = this.a;
        jVar.getClass();
        r rVar = new r(jVar);
        this.b = rVar;
        rVar.setTintList(colorStateList);
        if (mode != null) {
            this.b.setTintMode(mode);
        }
        com.google.android.material.shape.g gVar = this.b;
        FloatingActionButton floatingActionButton = this.v;
        gVar.k(floatingActionButton.getContext());
        if (i > 0) {
            Context context = floatingActionButton.getContext();
            com.google.android.material.shape.j jVar2 = this.a;
            jVar2.getClass();
            b bVar = new b(jVar2);
            int color = context.getColor(R.color.design_fab_stroke_top_outer_color);
            int color2 = context.getColor(R.color.design_fab_stroke_top_inner_color);
            int color3 = context.getColor(R.color.design_fab_stroke_end_inner_color);
            int color4 = context.getColor(R.color.design_fab_stroke_end_outer_color);
            bVar.i = color;
            bVar.j = color2;
            bVar.k = color3;
            bVar.l = color4;
            float f = i;
            if (bVar.h != f) {
                bVar.h = f;
                bVar.b.setStrokeWidth(f * 1.3333f);
                bVar.n = true;
                bVar.invalidateSelf();
            }
            if (colorStateList != null) {
                bVar.m = colorStateList.getColorForState(bVar.getState(), bVar.m);
            }
            bVar.p = colorStateList;
            bVar.n = true;
            bVar.invalidateSelf();
            this.d = bVar;
            b bVar2 = this.d;
            bVar2.getClass();
            com.google.android.material.shape.g gVar2 = this.b;
            gVar2.getClass();
            layerDrawable = new LayerDrawable(new Drawable[]{bVar2, gVar2});
        } else {
            this.d = null;
            layerDrawable = this.b;
        }
        RippleDrawable rippleDrawable = new RippleDrawable(com.google.android.material.ripple.a.b(colorStateList2), layerDrawable, null);
        this.c = rippleDrawable;
        this.e = rippleDrawable;
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void h() {
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void i() {
        r();
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void j(int[] iArr) {
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void k(float f, float f2, float f3) {
        FloatingActionButton floatingActionButton = this.v;
        if (floatingActionButton.getStateListAnimator() == this.N) {
            StateListAnimator stateListAnimator = new StateListAnimator();
            stateListAnimator.addState(q.H, s(f, f3));
            stateListAnimator.addState(q.I, s(f, f2));
            stateListAnimator.addState(q.J, s(f, f2));
            stateListAnimator.addState(q.K, s(f, f2));
            AnimatorSet animatorSet = new AnimatorSet();
            ArrayList arrayList = new ArrayList();
            arrayList.add(ObjectAnimator.ofFloat(floatingActionButton, "elevation", f).setDuration(0L));
            arrayList.add(ObjectAnimator.ofFloat(floatingActionButton, (Property<FloatingActionButton, Float>) View.TRANSLATION_Z, DefinitionKt.NO_Float_VALUE).setDuration(100L));
            animatorSet.playSequentially((Animator[]) arrayList.toArray(new Animator[0]));
            animatorSet.setInterpolator(q.C);
            stateListAnimator.addState(q.L, animatorSet);
            stateListAnimator.addState(q.M, s(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE));
            this.N = stateListAnimator;
            floatingActionButton.setStateListAnimator(stateListAnimator);
        }
        if (p()) {
            r();
        }
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void n(ColorStateList colorStateList) {
        Drawable drawable = this.c;
        if (drawable instanceof RippleDrawable) {
            ((RippleDrawable) drawable).setColor(com.google.android.material.ripple.a.b(colorStateList));
        } else {
            super.n(colorStateList);
        }
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final boolean p() {
        if (((FloatingActionButton) this.w.a).k) {
            return true;
        }
        return this.f && this.v.getSizeDimension() < this.k;
    }

    @Override // com.google.android.material.floatingactionbutton.q
    public final void q() {
    }

    public final AnimatorSet s(float f, float f2) {
        AnimatorSet animatorSet = new AnimatorSet();
        float[] fArr = {f};
        FloatingActionButton floatingActionButton = this.v;
        animatorSet.play(ObjectAnimator.ofFloat(floatingActionButton, "elevation", fArr).setDuration(0L)).with(ObjectAnimator.ofFloat(floatingActionButton, (Property<FloatingActionButton, Float>) View.TRANSLATION_Z, f2).setDuration(100L));
        animatorSet.setInterpolator(q.C);
        return animatorSet;
    }
}
