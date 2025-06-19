package com.google.android.material.circularreveal.cardview;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.FrameLayout;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3424a4;
import com.google.android.material.card.b;
import com.google.android.material.circularreveal.f;
import com.google.android.material.circularreveal.g;
import com.quizlet.data.repository.folderwithcreatorinclass.e;

/* loaded from: classes2.dex */
public class a extends b implements g {
    public final e o;

    public a(Context context) {
        this(context, 0);
    }

    @Override // com.google.android.material.circularreveal.g
    public final void a() {
        this.o.getClass();
    }

    @Override // com.google.android.material.circularreveal.g
    public final void b() {
        this.o.getClass();
    }

    @Override // com.google.android.material.circularreveal.g
    public final void c(Canvas canvas) {
        super.draw(canvas);
    }

    @Override // com.google.android.material.circularreveal.g
    public final boolean d() {
        return super.isOpaque();
    }

    @Override // android.view.View
    public final void draw(Canvas canvas) {
        e eVar = this.o;
        if (eVar != null) {
            eVar.e(canvas);
        } else {
            super.draw(canvas);
        }
    }

    public Drawable getCircularRevealOverlayDrawable() {
        return (Drawable) this.o.e;
    }

    @Override // com.google.android.material.circularreveal.g
    public int getCircularRevealScrimColor() {
        return ((Paint) this.o.c).getColor();
    }

    @Override // com.google.android.material.circularreveal.g
    public f getRevealInfo() {
        e eVar = this.o;
        f fVar = (f) eVar.d;
        if (fVar == null) {
            return null;
        }
        f fVar2 = new f(fVar);
        if (fVar2.c == Float.MAX_VALUE) {
            float f = fVar2.a;
            float f2 = fVar2.b;
            View view = (View) eVar.b;
            fVar2.c = AbstractC3424a4.b(f, f2, view.getWidth(), view.getHeight());
        }
        return fVar2;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [android.widget.FrameLayout, com.google.android.material.circularreveal.g] */
    @Override // android.view.View
    public final boolean isOpaque() {
        e eVar = this.o;
        if (eVar == null) {
            return super.isOpaque();
        }
        if (!((FrameLayout) eVar.a).d()) {
            return false;
        }
        f fVar = (f) eVar.d;
        return fVar == null || fVar.c == Float.MAX_VALUE;
    }

    @Override // com.google.android.material.circularreveal.g
    public void setCircularRevealOverlayDrawable(Drawable drawable) {
        e eVar = this.o;
        eVar.e = drawable;
        ((View) eVar.b).invalidate();
    }

    @Override // com.google.android.material.circularreveal.g
    public void setCircularRevealScrimColor(int i) {
        e eVar = this.o;
        ((Paint) eVar.c).setColor(i);
        ((View) eVar.b).invalidate();
    }

    @Override // com.google.android.material.circularreveal.g
    public void setRevealInfo(f fVar) {
        this.o.g(fVar);
    }

    public a(Context context, int i) {
        super(context, 0);
        this.o = new e(this);
    }
}
