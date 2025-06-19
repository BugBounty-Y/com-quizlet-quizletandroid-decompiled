package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.view.View;
import java.util.WeakHashMap;

/* renamed from: androidx.appcompat.widget.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0105q {
    public final View a;
    public o1 d;
    public o1 e;
    public o1 f;
    public int c = -1;
    public final C0112u b = C0112u.a();

    public C0105q(View view) {
        this.a = view;
    }

    public final void a() {
        View view = this.a;
        Drawable background = view.getBackground();
        if (background != null) {
            if (this.d != null) {
                if (this.f == null) {
                    this.f = new o1();
                }
                o1 o1Var = this.f;
                o1Var.c = null;
                o1Var.b = false;
                o1Var.d = null;
                o1Var.a = false;
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                ColorStateList colorStateListC = androidx.core.view.L.c(view);
                if (colorStateListC != null) {
                    o1Var.b = true;
                    o1Var.c = colorStateListC;
                }
                PorterDuff.Mode modeD = androidx.core.view.L.d(view);
                if (modeD != null) {
                    o1Var.a = true;
                    o1Var.d = modeD;
                }
                if (o1Var.b || o1Var.a) {
                    C0112u.e(background, o1Var, view.getDrawableState());
                    return;
                }
            }
            o1 o1Var2 = this.e;
            if (o1Var2 != null) {
                C0112u.e(background, o1Var2, view.getDrawableState());
                return;
            }
            o1 o1Var3 = this.d;
            if (o1Var3 != null) {
                C0112u.e(background, o1Var3, view.getDrawableState());
            }
        }
    }

    public final ColorStateList b() {
        o1 o1Var = this.e;
        if (o1Var != null) {
            return (ColorStateList) o1Var.c;
        }
        return null;
    }

    public final PorterDuff.Mode c() {
        o1 o1Var = this.e;
        if (o1Var != null) {
            return (PorterDuff.Mode) o1Var.d;
        }
        return null;
    }

    public final void d(AttributeSet attributeSet, int i) {
        ColorStateList colorStateListF;
        View view = this.a;
        Context context = view.getContext();
        int[] iArr = androidx.appcompat.a.B;
        com.quizlet.data.repository.classfolder.e eVarM = com.quizlet.data.repository.classfolder.e.m(context, attributeSet, iArr, i);
        TypedArray typedArray = (TypedArray) eVarM.c;
        View view2 = this.a;
        androidx.core.view.V.n(view2, view2.getContext(), iArr, attributeSet, (TypedArray) eVarM.c, i);
        try {
            if (typedArray.hasValue(0)) {
                this.c = typedArray.getResourceId(0, -1);
                C0112u c0112u = this.b;
                Context context2 = view.getContext();
                int i2 = this.c;
                synchronized (c0112u) {
                    colorStateListF = c0112u.a.f(context2, i2);
                }
                if (colorStateListF != null) {
                    g(colorStateListF);
                }
            }
            if (typedArray.hasValue(1)) {
                androidx.core.view.L.i(view, eVarM.e(1));
            }
            if (typedArray.hasValue(2)) {
                androidx.core.view.L.j(view, AbstractC0102o0.c(typedArray.getInt(2, -1), null));
            }
            eVarM.n();
        } catch (Throwable th) {
            eVarM.n();
            throw th;
        }
    }

    public final void e() {
        this.c = -1;
        g(null);
        a();
    }

    public final void f(int i) {
        ColorStateList colorStateListF;
        this.c = i;
        C0112u c0112u = this.b;
        if (c0112u != null) {
            Context context = this.a.getContext();
            synchronized (c0112u) {
                colorStateListF = c0112u.a.f(context, i);
            }
        } else {
            colorStateListF = null;
        }
        g(colorStateListF);
        a();
    }

    public final void g(ColorStateList colorStateList) {
        if (colorStateList != null) {
            if (this.d == null) {
                this.d = new o1();
            }
            o1 o1Var = this.d;
            o1Var.c = colorStateList;
            o1Var.b = true;
        } else {
            this.d = null;
        }
        a();
    }

    public final void h(ColorStateList colorStateList) {
        if (this.e == null) {
            this.e = new o1();
        }
        o1 o1Var = this.e;
        o1Var.c = colorStateList;
        o1Var.b = true;
        a();
    }

    public final void i(PorterDuff.Mode mode) {
        if (this.e == null) {
            this.e = new o1();
        }
        o1 o1Var = this.e;
        o1Var.d = mode;
        o1Var.a = true;
        a();
    }
}
