package com.google.android.material.card;

import android.animation.TimeInterpolator;
import android.animation.ValueAnimator;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Rect;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.util.AttributeSet;
import android.view.View;
import androidx.core.view.V;
import com.airbnb.lottie.s;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3430b4;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3460g4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.material.shape.g;
import com.google.android.material.shape.i;
import com.google.android.material.shape.j;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class d {
    public static final double y = Math.cos(Math.toRadians(45.0d));
    public static final ColorDrawable z;
    public final b a;
    public final g c;
    public final g d;
    public int e;
    public int f;
    public int g;
    public int h;
    public Drawable i;
    public Drawable j;
    public ColorStateList k;
    public ColorStateList l;
    public j m;
    public ColorStateList n;
    public RippleDrawable o;
    public LayerDrawable p;
    public g q;
    public boolean s;
    public ValueAnimator t;
    public final TimeInterpolator u;
    public final int v;
    public final int w;
    public final Rect b = new Rect();
    public boolean r = false;
    public float x = DefinitionKt.NO_Float_VALUE;

    static {
        z = Build.VERSION.SDK_INT <= 28 ? new ColorDrawable() : null;
    }

    public d(b bVar, AttributeSet attributeSet, int i) {
        this.a = bVar;
        g gVar = new g(bVar.getContext(), attributeSet, i, R.style.Widget_MaterialComponents_CardView);
        this.c = gVar;
        gVar.k(bVar.getContext());
        gVar.p();
        G4 g4F = gVar.a.a.f();
        TypedArray typedArrayObtainStyledAttributes = bVar.getContext().obtainStyledAttributes(attributeSet, com.google.android.material.a.f, i, R.style.CardView);
        if (typedArrayObtainStyledAttributes.hasValue(3)) {
            float dimension = typedArrayObtainStyledAttributes.getDimension(3, DefinitionKt.NO_Float_VALUE);
            g4F.e = new com.google.android.material.shape.a(dimension);
            g4F.f = new com.google.android.material.shape.a(dimension);
            g4F.g = new com.google.android.material.shape.a(dimension);
            g4F.h = new com.google.android.material.shape.a(dimension);
        }
        this.d = new g();
        h(g4F.a());
        this.u = AbstractC3430b4.e(bVar.getContext(), R.attr.motionEasingLinearInterpolator, com.google.android.material.animation.a.a);
        this.v = AbstractC3430b4.d(bVar.getContext(), R.attr.motionDurationShort2, 300);
        this.w = AbstractC3430b4.d(bVar.getContext(), R.attr.motionDurationShort1, 300);
        typedArrayObtainStyledAttributes.recycle();
    }

    public static float b(AbstractC3460g4 abstractC3460g4, float f) {
        return abstractC3460g4 instanceof i ? (float) ((1.0d - y) * f) : abstractC3460g4 instanceof com.google.android.material.shape.d ? f / 2.0f : DefinitionKt.NO_Float_VALUE;
    }

    public final float a() {
        AbstractC3460g4 abstractC3460g4 = this.m.a;
        g gVar = this.c;
        return Math.max(Math.max(b(abstractC3460g4, gVar.i()), b(this.m.b, gVar.a.a.f.a(gVar.g()))), Math.max(b(this.m.c, gVar.a.a.g.a(gVar.g())), b(this.m.d, gVar.a.a.h.a(gVar.g()))));
    }

    public final LayerDrawable c() {
        if (this.o == null) {
            int[] iArr = com.google.android.material.ripple.a.a;
            this.q = new g(this.m);
            this.o = new RippleDrawable(this.k, null, this.q);
        }
        if (this.p == null) {
            LayerDrawable layerDrawable = new LayerDrawable(new Drawable[]{this.o, this.d, this.j});
            this.p = layerDrawable;
            layerDrawable.setId(2, R.id.mtrl_card_checked_layer_id);
        }
        return this.p;
    }

    public final c d(Drawable drawable) {
        int iCeil;
        int i;
        b bVar = this.a;
        if (bVar.getUseCompatPadding()) {
            float maxCardElevation = bVar.getMaxCardElevation() * 1.5f;
            boolean zI = i();
            float fA = DefinitionKt.NO_Float_VALUE;
            int iCeil2 = (int) Math.ceil(maxCardElevation + (zI ? a() : 0.0f));
            float maxCardElevation2 = bVar.getMaxCardElevation();
            if (i()) {
                fA = a();
            }
            iCeil = (int) Math.ceil(maxCardElevation2 + fA);
            i = iCeil2;
        } else {
            iCeil = 0;
            i = 0;
        }
        return new c(drawable, iCeil, i, iCeil, i);
    }

    public final void e(int i, int i2) {
        int iCeil;
        int iCeil2;
        int i3;
        int i4;
        if (this.p != null) {
            b bVar = this.a;
            if (bVar.getUseCompatPadding()) {
                float maxCardElevation = bVar.getMaxCardElevation() * 1.5f;
                boolean zI = i();
                float fA = DefinitionKt.NO_Float_VALUE;
                iCeil = (int) Math.ceil((maxCardElevation + (zI ? a() : 0.0f)) * 2.0f);
                float maxCardElevation2 = bVar.getMaxCardElevation();
                if (i()) {
                    fA = a();
                }
                iCeil2 = (int) Math.ceil((maxCardElevation2 + fA) * 2.0f);
            } else {
                iCeil = 0;
                iCeil2 = 0;
            }
            int i5 = this.g;
            int i6 = (i5 & 8388613) == 8388613 ? ((i - this.e) - this.f) - iCeil2 : this.e;
            int i7 = (i5 & 80) == 80 ? this.e : ((i2 - this.e) - this.f) - iCeil;
            int i8 = (i5 & 8388613) == 8388613 ? this.e : ((i - this.e) - this.f) - iCeil2;
            int i9 = (i5 & 80) == 80 ? ((i2 - this.e) - this.f) - iCeil : this.e;
            WeakHashMap weakHashMap = V.a;
            if (bVar.getLayoutDirection() == 1) {
                i4 = i8;
                i3 = i6;
            } else {
                i3 = i8;
                i4 = i6;
            }
            this.p.setLayerInset(2, i4, i9, i3, i7);
        }
    }

    public final void f(boolean z2, boolean z3) {
        int i = 1;
        Drawable drawable = this.j;
        if (drawable != null) {
            float f = DefinitionKt.NO_Float_VALUE;
            if (!z3) {
                drawable.setAlpha(z2 ? 255 : 0);
                if (z2) {
                    f = 1.0f;
                }
                this.x = f;
                return;
            }
            if (z2) {
                f = 1.0f;
            }
            float f2 = z2 ? 1.0f - this.x : this.x;
            ValueAnimator valueAnimator = this.t;
            if (valueAnimator != null) {
                valueAnimator.cancel();
                this.t = null;
            }
            ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(this.x, f);
            this.t = valueAnimatorOfFloat;
            valueAnimatorOfFloat.addUpdateListener(new s(this, i));
            this.t.setInterpolator(this.u);
            this.t.setDuration((long) ((z2 ? this.v : this.w) * f2));
            this.t.start();
        }
    }

    public final void g(Drawable drawable) {
        if (drawable != null) {
            Drawable drawableMutate = drawable.mutate();
            this.j = drawableMutate;
            drawableMutate.setTintList(this.l);
            f(this.a.j, false);
        } else {
            this.j = z;
        }
        LayerDrawable layerDrawable = this.p;
        if (layerDrawable != null) {
            layerDrawable.setDrawableByLayerId(R.id.mtrl_card_checked_layer_id, this.j);
        }
    }

    public final void h(j jVar) {
        this.m = jVar;
        g gVar = this.c;
        gVar.setShapeAppearanceModel(jVar);
        gVar.w = !gVar.a.a.e(gVar.g());
        g gVar2 = this.d;
        if (gVar2 != null) {
            gVar2.setShapeAppearanceModel(jVar);
        }
        g gVar3 = this.q;
        if (gVar3 != null) {
            gVar3.setShapeAppearanceModel(jVar);
        }
    }

    public final boolean i() {
        b bVar = this.a;
        if (!bVar.getPreventCornerOverlap()) {
            return false;
        }
        g gVar = this.c;
        return gVar.a.a.e(gVar.g()) && bVar.getUseCompatPadding();
    }

    public final boolean j() {
        View view = this.a;
        if (view.isClickable()) {
            return true;
        }
        while (view.isDuplicateParentStateEnabled() && (view.getParent() instanceof View)) {
            view = (View) view.getParent();
        }
        return view.isClickable();
    }

    public final void k() {
        Drawable drawable = this.i;
        Drawable drawableC = j() ? c() : this.d;
        this.i = drawableC;
        if (drawable != drawableC) {
            b bVar = this.a;
            if (bVar.getForeground() instanceof InsetDrawable) {
                ((InsetDrawable) bVar.getForeground()).setDrawable(drawableC);
            } else {
                bVar.setForeground(d(drawableC));
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x001b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l() {
        /*
            r7 = this;
            com.google.android.material.card.b r0 = r7.a
            boolean r1 = r0.getPreventCornerOverlap()
            r2 = 0
            if (r1 == 0) goto L1b
            com.google.android.material.shape.g r1 = r7.c
            com.google.android.material.shape.f r3 = r1.a
            com.google.android.material.shape.j r3 = r3.a
            android.graphics.RectF r1 = r1.g()
            boolean r1 = r3.e(r1)
            if (r1 != 0) goto L1b
            r1 = 1
            goto L1c
        L1b:
            r1 = r2
        L1c:
            r3 = 0
            if (r1 != 0) goto L28
            boolean r1 = r7.i()
            if (r1 == 0) goto L26
            goto L28
        L26:
            r1 = r3
            goto L2c
        L28:
            float r1 = r7.a()
        L2c:
            boolean r4 = r0.getPreventCornerOverlap()
            if (r4 == 0) goto L44
            boolean r4 = r0.getUseCompatPadding()
            if (r4 == 0) goto L44
            r3 = 4607182418800017408(0x3ff0000000000000, double:1.0)
            double r5 = com.google.android.material.card.d.y
            double r3 = r3 - r5
            float r5 = r0.getCardViewRadius()
            double r5 = (double) r5
            double r3 = r3 * r5
            float r3 = (float) r3
        L44:
            float r1 = r1 - r3
            int r1 = (int) r1
            android.graphics.Rect r3 = r7.b
            int r4 = r3.left
            int r4 = r4 + r1
            int r5 = r3.top
            int r5 = r5 + r1
            int r6 = r3.right
            int r6 = r6 + r1
            int r3 = r3.bottom
            int r3 = r3 + r1
            android.graphics.Rect r1 = r0.c
            r1.set(r4, r5, r6, r3)
            androidx.compose.foundation.text.input.internal.u r0 = r0.e
            java.lang.Object r1 = r0.c
            androidx.cardview.widget.CardView r1 = (androidx.cardview.widget.CardView) r1
            boolean r1 = r1.getUseCompatPadding()
            if (r1 != 0) goto L69
            r0.s(r2, r2, r2, r2)
            return
        L69:
            java.lang.Object r1 = r0.b
            android.graphics.drawable.Drawable r1 = (android.graphics.drawable.Drawable) r1
            androidx.cardview.widget.a r1 = (androidx.cardview.widget.a) r1
            float r2 = r1.e
            float r1 = r1.a
            java.lang.Object r3 = r0.c
            androidx.cardview.widget.CardView r3 = (androidx.cardview.widget.CardView) r3
            boolean r4 = r3.getPreventCornerOverlap()
            float r4 = androidx.cardview.widget.b.a(r2, r1, r4)
            double r4 = (double) r4
            double r4 = java.lang.Math.ceil(r4)
            int r4 = (int) r4
            boolean r3 = r3.getPreventCornerOverlap()
            float r1 = androidx.cardview.widget.b.b(r2, r1, r3)
            double r1 = (double) r1
            double r1 = java.lang.Math.ceil(r1)
            int r1 = (int) r1
            r0.s(r4, r1, r4, r1)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.card.d.l():void");
    }

    public final void m() {
        boolean z2 = this.r;
        b bVar = this.a;
        if (!z2) {
            bVar.setBackgroundInternal(d(this.c));
        }
        bVar.setForeground(d(this.i));
    }
}
