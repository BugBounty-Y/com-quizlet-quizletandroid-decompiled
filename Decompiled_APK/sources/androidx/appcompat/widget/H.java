package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class H extends C {
    public final G e;
    public Drawable f;
    public ColorStateList g;
    public PorterDuff.Mode h;
    public boolean i;
    public boolean j;

    public H(G g) {
        super(g);
        this.g = null;
        this.h = null;
        this.i = false;
        this.j = false;
        this.e = g;
    }

    @Override // androidx.appcompat.widget.C
    public final void b(AttributeSet attributeSet, int i) {
        super.b(attributeSet, R.attr.seekBarStyle);
        G g = this.e;
        Context context = g.getContext();
        int[] iArr = androidx.appcompat.a.g;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, attributeSet, iArr, R.attr.seekBarStyle);
        androidx.core.view.V.n(g, g.getContext(), iArr, attributeSet, (TypedArray) eVarM.c, R.attr.seekBarStyle);
        Drawable drawableH = eVarM.h(0);
        if (drawableH != null) {
            g.setThumb(drawableH);
        }
        Drawable drawableF = eVarM.f(1);
        Drawable drawable = this.f;
        if (drawable != null) {
            drawable.setCallback(null);
        }
        this.f = drawableF;
        if (drawableF != null) {
            drawableF.setCallback(g);
            drawableF.setLayoutDirection(g.getLayoutDirection());
            if (drawableF.isStateful()) {
                drawableF.setState(g.getDrawableState());
            }
            f();
        }
        g.invalidate();
        TypedArray typedArray = (TypedArray) eVarM.c;
        if (typedArray.hasValue(3)) {
            this.h = AbstractC0102o0.c(typedArray.getInt(3, -1), this.h);
            this.j = true;
        }
        if (typedArray.hasValue(2)) {
            this.g = eVarM.e(2);
            this.i = true;
        }
        eVarM.n();
        f();
    }

    public final void f() {
        Drawable drawable = this.f;
        if (drawable != null) {
            if (this.i || this.j) {
                Drawable drawableMutate = drawable.mutate();
                this.f = drawableMutate;
                if (this.i) {
                    drawableMutate.setTintList(this.g);
                }
                if (this.j) {
                    this.f.setTintMode(this.h);
                }
                if (this.f.isStateful()) {
                    this.f.setState(this.e.getDrawableState());
                }
            }
        }
    }

    public final void g(Canvas canvas) {
        if (this.f != null) {
            int max = this.e.getMax();
            if (max > 1) {
                int intrinsicWidth = this.f.getIntrinsicWidth();
                int intrinsicHeight = this.f.getIntrinsicHeight();
                int i = intrinsicWidth >= 0 ? intrinsicWidth / 2 : 1;
                int i2 = intrinsicHeight >= 0 ? intrinsicHeight / 2 : 1;
                this.f.setBounds(-i, -i2, i, i2);
                float width = ((r0.getWidth() - r0.getPaddingLeft()) - r0.getPaddingRight()) / max;
                int iSave = canvas.save();
                canvas.translate(r0.getPaddingLeft(), r0.getHeight() / 2);
                for (int i3 = 0; i3 <= max; i3++) {
                    this.f.draw(canvas);
                    canvas.translate(width, DefinitionKt.NO_Float_VALUE);
                }
                canvas.restoreToCount(iSave);
            }
        }
    }
}
