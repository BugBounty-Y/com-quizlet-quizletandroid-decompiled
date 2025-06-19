package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.PorterDuff;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.widget.TextView;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.Arrays;

/* loaded from: classes.dex */
public final class Z {
    public final TextView a;
    public o1 b;
    public o1 c;
    public o1 d;
    public o1 e;
    public o1 f;
    public o1 g;
    public o1 h;
    public final C0088h0 i;
    public int j = 0;
    public int k = -1;
    public Typeface l;
    public boolean m;

    public Z(TextView textView) {
        this.a = textView;
        this.i = new C0088h0(textView);
    }

    public static o1 c(Context context, C0112u c0112u, int i) {
        ColorStateList colorStateListF;
        synchronized (c0112u) {
            colorStateListF = c0112u.a.f(context, i);
        }
        if (colorStateListF == null) {
            return null;
        }
        o1 o1Var = new o1();
        o1Var.b = true;
        o1Var.c = colorStateListF;
        return o1Var;
    }

    public final void a(Drawable drawable, o1 o1Var) {
        if (drawable == null || o1Var == null) {
            return;
        }
        C0112u.e(drawable, o1Var, this.a.getDrawableState());
    }

    public final void b() {
        o1 o1Var = this.b;
        TextView textView = this.a;
        if (o1Var != null || this.c != null || this.d != null || this.e != null) {
            Drawable[] compoundDrawables = textView.getCompoundDrawables();
            a(compoundDrawables[0], this.b);
            a(compoundDrawables[1], this.c);
            a(compoundDrawables[2], this.d);
            a(compoundDrawables[3], this.e);
        }
        if (this.f == null && this.g == null) {
            return;
        }
        Drawable[] compoundDrawablesRelative = textView.getCompoundDrawablesRelative();
        a(compoundDrawablesRelative[0], this.f);
        a(compoundDrawablesRelative[2], this.g);
    }

    public final ColorStateList d() {
        o1 o1Var = this.h;
        if (o1Var != null) {
            return (ColorStateList) o1Var.c;
        }
        return null;
    }

    public final PorterDuff.Mode e() {
        o1 o1Var = this.h;
        if (o1Var != null) {
            return (PorterDuff.Mode) o1Var.d;
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:226:0x0390  */
    /* JADX WARN: Removed duplicated region for block: B:228:0x0395  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x039c  */
    /* JADX WARN: Removed duplicated region for block: B:241:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(android.util.AttributeSet r26, int r27) {
        /*
            Method dump skipped, instructions count: 961
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.Z.f(android.util.AttributeSet, int):void");
    }

    public final void g(Context context, int i) {
        String string;
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(i, androidx.appcompat.a.y);
        com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e(context, typedArrayObtainStyledAttributes);
        boolean zHasValue = typedArrayObtainStyledAttributes.hasValue(14);
        TextView textView = this.a;
        if (zHasValue) {
            textView.setAllCaps(typedArrayObtainStyledAttributes.getBoolean(14, false));
        }
        if (typedArrayObtainStyledAttributes.hasValue(0) && typedArrayObtainStyledAttributes.getDimensionPixelSize(0, -1) == 0) {
            textView.setTextSize(0, DefinitionKt.NO_Float_VALUE);
        }
        m(context, eVar);
        if (typedArrayObtainStyledAttributes.hasValue(13) && (string = typedArrayObtainStyledAttributes.getString(13)) != null) {
            X.d(textView, string);
        }
        eVar.n();
        Typeface typeface = this.l;
        if (typeface != null) {
            textView.setTypeface(typeface, this.j);
        }
    }

    public final void h(int i, int i2, int i3, int i4) {
        C0088h0 c0088h0 = this.i;
        if (c0088h0.j()) {
            DisplayMetrics displayMetrics = c0088h0.j.getResources().getDisplayMetrics();
            c0088h0.k(TypedValue.applyDimension(i4, i, displayMetrics), TypedValue.applyDimension(i4, i2, displayMetrics), TypedValue.applyDimension(i4, i3, displayMetrics));
            if (c0088h0.h()) {
                c0088h0.a();
            }
        }
    }

    public final void i(int[] iArr, int i) {
        C0088h0 c0088h0 = this.i;
        if (c0088h0.j()) {
            int length = iArr.length;
            if (length > 0) {
                int[] iArrCopyOf = new int[length];
                if (i == 0) {
                    iArrCopyOf = Arrays.copyOf(iArr, length);
                } else {
                    DisplayMetrics displayMetrics = c0088h0.j.getResources().getDisplayMetrics();
                    for (int i2 = 0; i2 < length; i2++) {
                        iArrCopyOf[i2] = Math.round(TypedValue.applyDimension(i, iArr[i2], displayMetrics));
                    }
                }
                c0088h0.f = C0088h0.b(iArrCopyOf);
                if (!c0088h0.i()) {
                    throw new IllegalArgumentException("None of the preset sizes is valid: " + Arrays.toString(iArr));
                }
            } else {
                c0088h0.g = false;
            }
            if (c0088h0.h()) {
                c0088h0.a();
            }
        }
    }

    public final void j(int i) {
        C0088h0 c0088h0 = this.i;
        if (c0088h0.j()) {
            if (i == 0) {
                c0088h0.a = 0;
                c0088h0.d = -1.0f;
                c0088h0.e = -1.0f;
                c0088h0.c = -1.0f;
                c0088h0.f = new int[0];
                c0088h0.b = false;
                return;
            }
            if (i != 1) {
                throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Unknown auto-size text type: "));
            }
            DisplayMetrics displayMetrics = c0088h0.j.getResources().getDisplayMetrics();
            c0088h0.k(TypedValue.applyDimension(2, 12.0f, displayMetrics), TypedValue.applyDimension(2, 112.0f, displayMetrics), 1.0f);
            if (c0088h0.h()) {
                c0088h0.a();
            }
        }
    }

    public final void k(ColorStateList colorStateList) {
        if (this.h == null) {
            this.h = new o1();
        }
        o1 o1Var = this.h;
        o1Var.c = colorStateList;
        o1Var.b = colorStateList != null;
        this.b = o1Var;
        this.c = o1Var;
        this.d = o1Var;
        this.e = o1Var;
        this.f = o1Var;
        this.g = o1Var;
    }

    public final void l(PorterDuff.Mode mode) {
        if (this.h == null) {
            this.h = new o1();
        }
        o1 o1Var = this.h;
        o1Var.d = mode;
        o1Var.a = mode != null;
        this.b = o1Var;
        this.c = o1Var;
        this.d = o1Var;
        this.e = o1Var;
        this.f = o1Var;
        this.g = o1Var;
    }

    public final void m(Context context, com.quizlet.data.repository.classfolder.e eVar) {
        String string;
        int i = this.j;
        TypedArray typedArray = (TypedArray) eVar.c;
        this.j = typedArray.getInt(2, i);
        int i2 = Build.VERSION.SDK_INT;
        if (i2 >= 28) {
            int i3 = typedArray.getInt(11, -1);
            this.k = i3;
            if (i3 != -1) {
                this.j &= 2;
            }
        }
        if (!typedArray.hasValue(10) && !typedArray.hasValue(12)) {
            if (typedArray.hasValue(1)) {
                this.m = false;
                int i4 = typedArray.getInt(1, 1);
                if (i4 == 1) {
                    this.l = Typeface.SANS_SERIF;
                    return;
                } else if (i4 == 2) {
                    this.l = Typeface.SERIF;
                    return;
                } else {
                    if (i4 != 3) {
                        return;
                    }
                    this.l = Typeface.MONOSPACE;
                    return;
                }
            }
            return;
        }
        this.l = null;
        int i5 = typedArray.hasValue(12) ? 12 : 10;
        int i6 = this.k;
        int i7 = this.j;
        if (!context.isRestricted()) {
            try {
                Typeface typefaceI = eVar.i(i5, this.j, new U(this, i6, i7, new WeakReference(this.a)));
                if (typefaceI != null) {
                    if (i2 < 28 || this.k == -1) {
                        this.l = typefaceI;
                    } else {
                        this.l = Y.a(Typeface.create(typefaceI, 0), this.k, (this.j & 2) != 0);
                    }
                }
                this.m = this.l == null;
            } catch (Resources.NotFoundException | UnsupportedOperationException unused) {
            }
        }
        if (this.l != null || (string = typedArray.getString(i5)) == null) {
            return;
        }
        if (Build.VERSION.SDK_INT < 28 || this.k == -1) {
            this.l = Typeface.create(string, this.j);
        } else {
            this.l = Y.a(Typeface.create(string, 0), this.k, (this.j & 2) != 0);
        }
    }
}
