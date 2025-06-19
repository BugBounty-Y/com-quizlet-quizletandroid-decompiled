package androidx.appcompat.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.LayerDrawable;
import android.util.TypedValue;
import androidx.collection.C0219q;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

/* loaded from: classes.dex */
public final class N0 {
    public static N0 g;
    public WeakHashMap a;
    public final WeakHashMap b = new WeakHashMap(0);
    public TypedValue c;
    public boolean d;
    public androidx.camera.camera2.internal.c0 e;
    public static final PorterDuff.Mode f = PorterDuff.Mode.SRC_IN;
    public static final M0 h = new M0(6);

    public static synchronized N0 b() {
        try {
            if (g == null) {
                g = new N0();
            }
        } catch (Throwable th) {
            throw th;
        }
        return g;
    }

    public static synchronized PorterDuffColorFilter e(int i, PorterDuff.Mode mode) {
        PorterDuffColorFilter porterDuffColorFilter;
        M0 m0 = h;
        m0.getClass();
        int i2 = (31 + i) * 31;
        porterDuffColorFilter = (PorterDuffColorFilter) m0.g(Integer.valueOf(mode.hashCode() + i2));
        if (porterDuffColorFilter == null) {
            porterDuffColorFilter = new PorterDuffColorFilter(i, mode);
        }
        return porterDuffColorFilter;
    }

    public final Drawable a(Context context, int i) throws Resources.NotFoundException {
        Drawable drawableNewDrawable;
        WeakReference weakReference;
        if (this.c == null) {
            this.c = new TypedValue();
        }
        TypedValue typedValue = this.c;
        context.getResources().getValue(i, typedValue, true);
        long j = (typedValue.assetCookie << 32) | typedValue.data;
        synchronized (this) {
            C0219q c0219q = (C0219q) this.b.get(context);
            drawableNewDrawable = null;
            if (c0219q != null && (weakReference = (WeakReference) c0219q.c(j)) != null) {
                Drawable.ConstantState constantState = (Drawable.ConstantState) weakReference.get();
                if (constantState != null) {
                    drawableNewDrawable = constantState.newDrawable(context.getResources());
                } else {
                    c0219q.h(j);
                }
            }
        }
        if (drawableNewDrawable != null) {
            return drawableNewDrawable;
        }
        LayerDrawable layerDrawableP = null;
        if (this.e != null) {
            if (i == R.drawable.abc_cab_background_top_material) {
                layerDrawableP = new LayerDrawable(new Drawable[]{c(context, R.drawable.abc_cab_background_internal_bg), c(context, 2131230785)});
            } else if (i == R.drawable.abc_ratingbar_material) {
                layerDrawableP = androidx.camera.camera2.internal.c0.p(this, context, R.dimen.abc_star_big);
            } else if (i == R.drawable.abc_ratingbar_indicator_material) {
                layerDrawableP = androidx.camera.camera2.internal.c0.p(this, context, R.dimen.abc_star_medium);
            } else if (i == R.drawable.abc_ratingbar_small_material) {
                layerDrawableP = androidx.camera.camera2.internal.c0.p(this, context, R.dimen.abc_star_small);
            }
        }
        if (layerDrawableP == null) {
            return layerDrawableP;
        }
        layerDrawableP.setChangingConfigurations(typedValue.changingConfigurations);
        synchronized (this) {
            try {
                Drawable.ConstantState constantState2 = layerDrawableP.getConstantState();
                if (constantState2 != null) {
                    C0219q c0219q2 = (C0219q) this.b.get(context);
                    if (c0219q2 == null) {
                        c0219q2 = new C0219q((Object) null);
                        this.b.put(context, c0219q2);
                    }
                    c0219q2.g(j, new WeakReference(constantState2));
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return layerDrawableP;
    }

    public final synchronized Drawable c(Context context, int i) {
        return d(context, i, false);
    }

    public final synchronized Drawable d(Context context, int i, boolean z) {
        Drawable drawableA;
        try {
            if (!this.d) {
                this.d = true;
                Drawable drawableC = c(context, R.drawable.abc_vector_test);
                if (drawableC == null || (!(drawableC instanceof androidx.vectordrawable.graphics.drawable.p) && !"android.graphics.drawable.VectorDrawable".equals(drawableC.getClass().getName()))) {
                    this.d = false;
                    throw new IllegalStateException("This app has been built with an incorrect configuration. Please configure your build for VectorDrawableCompat.");
                }
            }
            drawableA = a(context, i);
            if (drawableA == null) {
                drawableA = context.getDrawable(i);
            }
            if (drawableA != null) {
                drawableA = g(context, i, z, drawableA);
            }
            if (drawableA != null) {
                AbstractC0102o0.a(drawableA);
            }
        } catch (Throwable th) {
            throw th;
        }
        return drawableA;
    }

    public final synchronized ColorStateList f(Context context, int i) {
        ColorStateList colorStateList;
        androidx.collection.W w;
        WeakHashMap weakHashMap = this.a;
        ColorStateList colorStateListR = null;
        colorStateList = (weakHashMap == null || (w = (androidx.collection.W) weakHashMap.get(context)) == null) ? null : (ColorStateList) w.d(i);
        if (colorStateList == null) {
            androidx.camera.camera2.internal.c0 c0Var = this.e;
            if (c0Var != null) {
                colorStateListR = c0Var.r(context, i);
            }
            if (colorStateListR != null) {
                if (this.a == null) {
                    this.a = new WeakHashMap();
                }
                androidx.collection.W w2 = (androidx.collection.W) this.a.get(context);
                if (w2 == null) {
                    w2 = new androidx.collection.W(0);
                    this.a.put(context, w2);
                }
                w2.b(i, colorStateListR);
            }
            colorStateList = colorStateListR;
        }
        return colorStateList;
    }

    /* JADX WARN: Removed duplicated region for block: B:49:0x00eb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.drawable.Drawable g(android.content.Context r8, int r9, boolean r10, android.graphics.drawable.Drawable r11) {
        /*
            Method dump skipped, instructions count: 262
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.widget.N0.g(android.content.Context, int, boolean, android.graphics.drawable.Drawable):android.graphics.drawable.Drawable");
    }
}
