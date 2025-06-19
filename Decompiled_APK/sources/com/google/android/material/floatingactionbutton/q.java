package com.google.android.material.floatingactionbutton;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.FloatEvaluator;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.graphics.Matrix;
import android.graphics.PorterDuff;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.os.Build;
import android.util.Property;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.V3;
import com.google.android.material.bottomappbar.BottomAppBar;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class q {
    public static final androidx.interpolator.view.animation.a C = com.google.android.material.animation.a.c;
    public static final int D = R.attr.motionDurationLong2;
    public static final int E = R.attr.motionEasingEmphasizedInterpolator;
    public static final int F = R.attr.motionDurationMedium1;
    public static final int G = R.attr.motionEasingEmphasizedAccelerateInterpolator;
    public static final int[] H = {android.R.attr.state_pressed, android.R.attr.state_enabled};
    public static final int[] I = {android.R.attr.state_hovered, android.R.attr.state_focused, android.R.attr.state_enabled};
    public static final int[] J = {android.R.attr.state_focused, android.R.attr.state_enabled};
    public static final int[] K = {android.R.attr.state_hovered, android.R.attr.state_enabled};
    public static final int[] L = {android.R.attr.state_enabled};
    public static final int[] M = new int[0];
    public androidx.coordinatorlayout.widget.f B;
    public com.google.android.material.shape.j a;
    public com.google.android.material.shape.g b;
    public Drawable c;
    public b d;
    public LayerDrawable e;
    public boolean f;
    public float h;
    public float i;
    public float j;
    public int k;
    public Animator l;
    public com.google.android.material.animation.f m;
    public com.google.android.material.animation.f n;
    public float o;
    public int q;
    public ArrayList s;
    public ArrayList t;
    public ArrayList u;
    public final FloatingActionButton v;
    public final com.google.firebase.platforminfo.c w;
    public boolean g = true;
    public float p = 1.0f;
    public int r = 0;
    public final Rect x = new Rect();
    public final RectF y = new RectF();
    public final RectF z = new RectF();
    public final Matrix A = new Matrix();

    public q(FloatingActionButton floatingActionButton, com.google.firebase.platforminfo.c cVar) {
        this.v = floatingActionButton;
        this.w = cVar;
        com.quizlet.data.repository.folderset.c cVar2 = new com.quizlet.data.repository.folderset.c(8);
        s sVar = (s) this;
        cVar2.l(H, d(new o(sVar, 1)));
        cVar2.l(I, d(new o(sVar, 0)));
        cVar2.l(J, d(new o(sVar, 0)));
        cVar2.l(K, d(new o(sVar, 0)));
        cVar2.l(L, d(new o(sVar, 2)));
        cVar2.l(M, d(new n(sVar)));
        this.o = floatingActionButton.getRotation();
    }

    public static ValueAnimator d(p pVar) {
        ValueAnimator valueAnimator = new ValueAnimator();
        valueAnimator.setInterpolator(C);
        valueAnimator.setDuration(100L);
        valueAnimator.addListener(pVar);
        valueAnimator.addUpdateListener(pVar);
        valueAnimator.setFloatValues(DefinitionKt.NO_Float_VALUE, 1.0f);
        return valueAnimator;
    }

    public final void a(float f, Matrix matrix) {
        matrix.reset();
        if (this.v.getDrawable() == null || this.q == 0) {
            return;
        }
        RectF rectF = this.y;
        RectF rectF2 = this.z;
        rectF.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, r0.getIntrinsicWidth(), r0.getIntrinsicHeight());
        float f2 = this.q;
        rectF2.set(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, f2, f2);
        matrix.setRectToRect(rectF, rectF2, Matrix.ScaleToFit.CENTER);
        float f3 = this.q / 2.0f;
        matrix.postScale(f, f, f3, f3);
    }

    public final AnimatorSet b(com.google.android.material.animation.f fVar, float f, float f2, float f3) {
        ArrayList arrayList = new ArrayList();
        Property property = View.ALPHA;
        float[] fArr = {f};
        FloatingActionButton floatingActionButton = this.v;
        ObjectAnimator objectAnimatorOfFloat = ObjectAnimator.ofFloat(floatingActionButton, (Property<FloatingActionButton, Float>) property, fArr);
        fVar.f("opacity").a(objectAnimatorOfFloat);
        arrayList.add(objectAnimatorOfFloat);
        ObjectAnimator objectAnimatorOfFloat2 = ObjectAnimator.ofFloat(floatingActionButton, (Property<FloatingActionButton, Float>) View.SCALE_X, f2);
        fVar.f("scale").a(objectAnimatorOfFloat2);
        int i = Build.VERSION.SDK_INT;
        if (i == 26) {
            m mVar = new m();
            mVar.b = new FloatEvaluator();
            objectAnimatorOfFloat2.setEvaluator(mVar);
        }
        arrayList.add(objectAnimatorOfFloat2);
        ObjectAnimator objectAnimatorOfFloat3 = ObjectAnimator.ofFloat(floatingActionButton, (Property<FloatingActionButton, Float>) View.SCALE_Y, f2);
        fVar.f("scale").a(objectAnimatorOfFloat3);
        if (i == 26) {
            m mVar2 = new m();
            mVar2.b = new FloatEvaluator();
            objectAnimatorOfFloat3.setEvaluator(mVar2);
        }
        arrayList.add(objectAnimatorOfFloat3);
        Matrix matrix = this.A;
        a(f3, matrix);
        ObjectAnimator objectAnimatorOfObject = ObjectAnimator.ofObject(floatingActionButton, new com.google.android.material.animation.e(), new k(this), new Matrix(matrix));
        fVar.f("iconScale").a(objectAnimatorOfObject);
        arrayList.add(objectAnimatorOfObject);
        AnimatorSet animatorSet = new AnimatorSet();
        V3.b(animatorSet, arrayList);
        return animatorSet;
    }

    public final AnimatorSet c(float f, float f2, float f3, int i, int i2) {
        AnimatorSet animatorSet = new AnimatorSet();
        ArrayList arrayList = new ArrayList();
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        FloatingActionButton floatingActionButton = this.v;
        valueAnimatorOfFloat.addUpdateListener(new l(this, floatingActionButton.getAlpha(), f, floatingActionButton.getScaleX(), f2, floatingActionButton.getScaleY(), this.p, f3, new Matrix(this.A)));
        arrayList.add(valueAnimatorOfFloat);
        V3.b(animatorSet, arrayList);
        animatorSet.setDuration(AbstractC3430b4.d(floatingActionButton.getContext(), i, floatingActionButton.getContext().getResources().getInteger(R.integer.material_motion_duration_long_1)));
        animatorSet.setInterpolator(AbstractC3430b4.e(floatingActionButton.getContext(), i2, com.google.android.material.animation.a.b));
        return animatorSet;
    }

    public abstract float e();

    public void f(Rect rect) {
        int iMax = this.f ? Math.max((this.k - this.v.getSizeDimension()) / 2, 0) : 0;
        int iMax2 = Math.max(iMax, (int) Math.ceil(this.g ? e() + this.j : DefinitionKt.NO_Float_VALUE));
        int iMax3 = Math.max(iMax, (int) Math.ceil(r0 * 1.5f));
        rect.set(iMax2, iMax3, iMax2, iMax3);
    }

    public abstract void g(ColorStateList colorStateList, PorterDuff.Mode mode, ColorStateList colorStateList2, int i);

    public abstract void h();

    public abstract void i();

    public abstract void j(int[] iArr);

    public abstract void k(float f, float f2, float f3);

    public final void l() {
        ArrayList arrayList = this.u;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                h hVar = (h) it2.next();
                com.google.firebase.platforminfo.c cVar = hVar.a;
                cVar.getClass();
                BottomAppBar bottomAppBar = (BottomAppBar) cVar.a;
                com.google.android.material.shape.g gVar = bottomAppBar.i1;
                FloatingActionButton floatingActionButton = hVar.b;
                gVar.n((floatingActionButton.getVisibility() == 0 && bottomAppBar.n1 == 1) ? floatingActionButton.getScaleY() : DefinitionKt.NO_Float_VALUE);
            }
        }
    }

    public final void m() {
        ArrayList arrayList = this.u;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                h hVar = (h) it2.next();
                com.google.firebase.platforminfo.c cVar = hVar.a;
                cVar.getClass();
                BottomAppBar bottomAppBar = (BottomAppBar) cVar.a;
                if (bottomAppBar.n1 == 1) {
                    FloatingActionButton floatingActionButton = hVar.b;
                    float translationX = floatingActionButton.getTranslationX();
                    float f = bottomAppBar.getTopEdgeTreatment().f;
                    com.google.android.material.shape.g gVar = bottomAppBar.i1;
                    if (f != translationX) {
                        bottomAppBar.getTopEdgeTreatment().f = translationX;
                        gVar.invalidateSelf();
                    }
                    float f2 = -floatingActionButton.getTranslationY();
                    float scaleY = DefinitionKt.NO_Float_VALUE;
                    float fMax = Math.max(DefinitionKt.NO_Float_VALUE, f2);
                    if (bottomAppBar.getTopEdgeTreatment().e != fMax) {
                        bottomAppBar.getTopEdgeTreatment().y(fMax);
                        gVar.invalidateSelf();
                    }
                    if (floatingActionButton.getVisibility() == 0) {
                        scaleY = floatingActionButton.getScaleY();
                    }
                    gVar.n(scaleY);
                }
            }
        }
    }

    public void n(ColorStateList colorStateList) {
        Drawable drawable = this.c;
        if (drawable != null) {
            drawable.setTintList(com.google.android.material.ripple.a.b(colorStateList));
        }
    }

    public final void o(com.google.android.material.shape.j jVar) {
        this.a = jVar;
        com.google.android.material.shape.g gVar = this.b;
        if (gVar != null) {
            gVar.setShapeAppearanceModel(jVar);
        }
        Object obj = this.c;
        if (obj instanceof com.google.android.material.shape.s) {
            ((com.google.android.material.shape.s) obj).setShapeAppearanceModel(jVar);
        }
        b bVar = this.d;
        if (bVar != null) {
            bVar.o = jVar;
            bVar.invalidateSelf();
        }
    }

    public abstract boolean p();

    public abstract void q();

    public final void r() {
        Rect rect = this.x;
        f(rect);
        AbstractC3242q6.g(this.e, "Didn't initialize content background");
        boolean zP = p();
        com.google.firebase.platforminfo.c cVar = this.w;
        if (zP) {
            super/*android.view.View*/.setBackgroundDrawable(new InsetDrawable((Drawable) this.e, rect.left, rect.top, rect.right, rect.bottom));
        } else {
            LayerDrawable layerDrawable = this.e;
            if (layerDrawable != null) {
                super/*android.view.View*/.setBackgroundDrawable(layerDrawable);
            } else {
                cVar.getClass();
            }
        }
        int i = rect.left;
        int i2 = rect.top;
        int i3 = rect.right;
        int i4 = rect.bottom;
        FloatingActionButton floatingActionButton = (FloatingActionButton) cVar.a;
        floatingActionButton.l.set(i, i2, i3, i4);
        int i5 = floatingActionButton.i;
        floatingActionButton.setPadding(i + i5, i2 + i5, i3 + i5, i4 + i5);
    }
}
