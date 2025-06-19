package com.google.android.material.button;

import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import android.graphics.drawable.RippleDrawable;
import androidx.core.view.V;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.shape.g;
import com.google.android.material.shape.j;
import com.google.android.material.shape.s;
import com.quizlet.quizletandroid.R;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class c {
    public final MaterialButton a;
    public j b;
    public int c;
    public int d;
    public int e;
    public int f;
    public int g;
    public int h;
    public PorterDuff.Mode i;
    public ColorStateList j;
    public ColorStateList k;
    public ColorStateList l;
    public g m;
    public boolean q;
    public RippleDrawable s;
    public int t;
    public boolean n = false;
    public boolean o = false;
    public boolean p = false;
    public boolean r = true;

    public c(MaterialButton materialButton, j jVar) {
        this.a = materialButton;
        this.b = jVar;
    }

    public final s a() {
        RippleDrawable rippleDrawable = this.s;
        if (rippleDrawable == null || rippleDrawable.getNumberOfLayers() <= 1) {
            return null;
        }
        return this.s.getNumberOfLayers() > 2 ? (s) this.s.getDrawable(2) : (s) this.s.getDrawable(1);
    }

    public final g b(boolean z) {
        RippleDrawable rippleDrawable = this.s;
        if (rippleDrawable == null || rippleDrawable.getNumberOfLayers() <= 0) {
            return null;
        }
        return (g) ((LayerDrawable) ((InsetDrawable) this.s.getDrawable(0)).getDrawable()).getDrawable(!z ? 1 : 0);
    }

    public final void c(j jVar) {
        this.b = jVar;
        if (b(false) != null) {
            b(false).setShapeAppearanceModel(jVar);
        }
        if (b(true) != null) {
            b(true).setShapeAppearanceModel(jVar);
        }
        if (a() != null) {
            a().setShapeAppearanceModel(jVar);
        }
    }

    public final void d(int i, int i2) {
        WeakHashMap weakHashMap = V.a;
        MaterialButton materialButton = this.a;
        int paddingStart = materialButton.getPaddingStart();
        int paddingTop = materialButton.getPaddingTop();
        int paddingEnd = materialButton.getPaddingEnd();
        int paddingBottom = materialButton.getPaddingBottom();
        int i3 = this.e;
        int i4 = this.f;
        this.f = i2;
        this.e = i;
        if (!this.o) {
            e();
        }
        materialButton.setPaddingRelative(paddingStart, (paddingTop + i) - i3, paddingEnd, (paddingBottom + i2) - i4);
    }

    public final void e() {
        g gVar = new g(this.b);
        MaterialButton materialButton = this.a;
        gVar.k(materialButton.getContext());
        gVar.setTintList(this.j);
        PorterDuff.Mode mode = this.i;
        if (mode != null) {
            gVar.setTintMode(mode);
        }
        float f = this.h;
        ColorStateList colorStateList = this.k;
        gVar.a.j = f;
        gVar.invalidateSelf();
        gVar.r(colorStateList);
        g gVar2 = new g(this.b);
        gVar2.setTint(0);
        float f2 = this.h;
        int iB = this.n ? X3.b(R.attr.colorSurface, materialButton) : 0;
        gVar2.a.j = f2;
        gVar2.invalidateSelf();
        gVar2.r(ColorStateList.valueOf(iB));
        g gVar3 = new g(this.b);
        this.m = gVar3;
        gVar3.setTint(-1);
        RippleDrawable rippleDrawable = new RippleDrawable(com.google.android.material.ripple.a.b(this.l), new InsetDrawable((Drawable) new LayerDrawable(new Drawable[]{gVar2, gVar}), this.c, this.e, this.d, this.f), this.m);
        this.s = rippleDrawable;
        materialButton.setInternalBackground(rippleDrawable);
        g gVarB = b(false);
        if (gVarB != null) {
            gVarB.l(this.t);
            gVarB.setState(materialButton.getDrawableState());
        }
    }

    public final void f() {
        g gVarB = b(false);
        g gVarB2 = b(true);
        if (gVarB != null) {
            float f = this.h;
            ColorStateList colorStateList = this.k;
            gVarB.a.j = f;
            gVarB.invalidateSelf();
            gVarB.r(colorStateList);
            if (gVarB2 != null) {
                float f2 = this.h;
                int iB = this.n ? X3.b(R.attr.colorSurface, this.a) : 0;
                gVarB2.a.j = f2;
                gVarB2.invalidateSelf();
                gVarB2.r(ColorStateList.valueOf(iB));
            }
        }
    }
}
