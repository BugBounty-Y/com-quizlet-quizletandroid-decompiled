package com.google.android.material.circularreveal;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3424a4;

/* loaded from: classes2.dex */
public class b extends FrameLayout implements g {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e a;

    public b(@NonNull Context context) {
        this(context, 0);
    }

    @Override // com.google.android.material.circularreveal.g
    public final void a() {
        this.a.getClass();
    }

    @Override // com.google.android.material.circularreveal.g
    public final void b() {
        this.a.getClass();
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
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.a;
        if (eVar != null) {
            eVar.e(canvas);
        } else {
            super.draw(canvas);
        }
    }

    public Drawable getCircularRevealOverlayDrawable() {
        return (Drawable) this.a.e;
    }

    @Override // com.google.android.material.circularreveal.g
    public int getCircularRevealScrimColor() {
        return ((Paint) this.a.c).getColor();
    }

    @Override // com.google.android.material.circularreveal.g
    public f getRevealInfo() {
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.a;
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
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.a;
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
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.a;
        eVar.e = drawable;
        ((View) eVar.b).invalidate();
    }

    @Override // com.google.android.material.circularreveal.g
    public void setCircularRevealScrimColor(int i) {
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.a;
        ((Paint) eVar.c).setColor(i);
        ((View) eVar.b).invalidate();
    }

    @Override // com.google.android.material.circularreveal.g
    public void setRevealInfo(f fVar) {
        this.a.g(fVar);
    }

    public b(Context context, int i) {
        super(context, null);
        this.a = new com.quizlet.data.repository.folderwithcreatorinclass.e(this);
    }
}
