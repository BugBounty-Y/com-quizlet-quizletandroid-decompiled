package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;

/* renamed from: androidx.appcompat.widget.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0112u {
    public static final PorterDuff.Mode b = PorterDuff.Mode.SRC_IN;
    public static C0112u c;
    public N0 a;

    public static synchronized C0112u a() {
        try {
            if (c == null) {
                d();
            }
        } catch (Throwable th) {
            throw th;
        }
        return c;
    }

    public static synchronized PorterDuffColorFilter c(int i, PorterDuff.Mode mode) {
        return N0.e(i, mode);
    }

    public static synchronized void d() {
        if (c == null) {
            C0112u c0112u = new C0112u();
            c = c0112u;
            c0112u.a = N0.b();
            N0 n0 = c.a;
            androidx.camera.camera2.internal.c0 c0Var = new androidx.camera.camera2.internal.c0(1);
            synchronized (n0) {
                n0.e = c0Var;
            }
        }
    }

    public static void e(Drawable drawable, o1 o1Var, int[] iArr) {
        PorterDuff.Mode mode = N0.f;
        int[] state = drawable.getState();
        if (drawable.mutate() == drawable) {
            if ((drawable instanceof LayerDrawable) && drawable.isStateful()) {
                drawable.setState(new int[0]);
                drawable.setState(state);
            }
            boolean z = o1Var.b;
            if (!z && !o1Var.a) {
                drawable.clearColorFilter();
                return;
            }
            PorterDuffColorFilter porterDuffColorFilterE = null;
            ColorStateList colorStateList = z ? (ColorStateList) o1Var.c : null;
            PorterDuff.Mode mode2 = o1Var.a ? (PorterDuff.Mode) o1Var.d : N0.f;
            if (colorStateList != null && mode2 != null) {
                porterDuffColorFilterE = N0.e(colorStateList.getColorForState(iArr, 0), mode2);
            }
            drawable.setColorFilter(porterDuffColorFilterE);
        }
    }

    public final synchronized Drawable b(Context context, int i) {
        return this.a.c(context, i);
    }
}
