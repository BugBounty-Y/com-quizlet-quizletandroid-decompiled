package com.google.android.material.badge;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import com.google.android.material.internal.m;
import com.google.android.material.internal.n;
import com.google.android.material.internal.p;
import com.google.android.material.resources.e;
import com.google.android.material.shape.g;
import com.google.android.material.shape.j;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import java.text.NumberFormat;

/* loaded from: classes2.dex */
public final class a extends Drawable implements m {
    public final WeakReference a;
    public final g b;
    public final n c;
    public final Rect d;
    public final b e;
    public float f;
    public float g;
    public final int h;
    public float i;
    public float j;
    public float k;
    public WeakReference l;
    public WeakReference m;

    public a(Context context) {
        e eVar;
        WeakReference weakReference = new WeakReference(context);
        this.a = weakReference;
        p.e(context, p.b, "Theme.MaterialComponents");
        this.d = new Rect();
        n nVar = new n(this);
        this.c = nVar;
        TextPaint textPaint = nVar.a;
        textPaint.setTextAlign(Paint.Align.CENTER);
        b bVar = new b(context);
        this.e = bVar;
        boolean zE = e();
        BadgeState$State badgeState$State = bVar.b;
        g gVar = new g(j.a(context, zE ? badgeState$State.g.intValue() : badgeState$State.e.intValue(), e() ? badgeState$State.h.intValue() : badgeState$State.f.intValue(), new com.google.android.material.shape.a(0)).a());
        this.b = gVar;
        g();
        Context context2 = (Context) weakReference.get();
        if (context2 != null && nVar.g != (eVar = new e(context2, badgeState$State.d.intValue()))) {
            nVar.b(eVar, context2);
            textPaint.setColor(badgeState$State.c.intValue());
            invalidateSelf();
            i();
            invalidateSelf();
        }
        int i = badgeState$State.l;
        if (i != -2) {
            this.h = ((int) Math.pow(10.0d, i - 1.0d)) - 1;
        } else {
            this.h = badgeState$State.m;
        }
        nVar.e = true;
        i();
        invalidateSelf();
        nVar.e = true;
        g();
        i();
        invalidateSelf();
        textPaint.setAlpha(getAlpha());
        invalidateSelf();
        ColorStateList colorStateListValueOf = ColorStateList.valueOf(badgeState$State.b.intValue());
        if (gVar.a.c != colorStateListValueOf) {
            gVar.m(colorStateListValueOf);
            invalidateSelf();
        }
        textPaint.setColor(badgeState$State.c.intValue());
        invalidateSelf();
        WeakReference weakReference2 = this.l;
        if (weakReference2 != null && weakReference2.get() != null) {
            View view = (View) this.l.get();
            WeakReference weakReference3 = this.m;
            h(view, weakReference3 != null ? (FrameLayout) weakReference3.get() : null);
        }
        i();
        setVisible(badgeState$State.t.booleanValue(), false);
    }

    @Override // com.google.android.material.internal.m
    public final void a() {
        invalidateSelf();
    }

    public final String b() {
        b bVar = this.e;
        BadgeState$State badgeState$State = bVar.b;
        String str = badgeState$State.j;
        boolean z = str != null;
        WeakReference weakReference = this.a;
        if (z) {
            int i = badgeState$State.l;
            if (i == -2 || str == null || str.length() <= i) {
                return str;
            }
            Context context = (Context) weakReference.get();
            if (context == null) {
                return "";
            }
            return String.format(context.getString(R.string.m3_exceed_max_badge_text_suffix), str.substring(0, i - 1), "…");
        }
        if (!f()) {
            return null;
        }
        int i2 = this.h;
        BadgeState$State badgeState$State2 = bVar.b;
        if (i2 == -2 || d() <= this.h) {
            return NumberFormat.getInstance(badgeState$State2.n).format(d());
        }
        Context context2 = (Context) weakReference.get();
        return context2 == null ? "" : String.format(badgeState$State2.n, context2.getString(R.string.mtrl_exceed_max_badge_number_suffix), Integer.valueOf(this.h), "+");
    }

    public final FrameLayout c() {
        WeakReference weakReference = this.m;
        if (weakReference != null) {
            return (FrameLayout) weakReference.get();
        }
        return null;
    }

    public final int d() {
        int i = this.e.b.k;
        if (i != -1) {
            return i;
        }
        return 0;
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        String strB;
        if (getBounds().isEmpty() || getAlpha() == 0 || !isVisible()) {
            return;
        }
        this.b.draw(canvas);
        if (!e() || (strB = b()) == null) {
            return;
        }
        Rect rect = new Rect();
        n nVar = this.c;
        nVar.a.getTextBounds(strB, 0, strB.length(), rect);
        float fExactCenterY = this.g - rect.exactCenterY();
        canvas.drawText(strB, this.f, rect.bottom <= 0 ? (int) fExactCenterY : Math.round(fExactCenterY), nVar.a);
    }

    public final boolean e() {
        return this.e.b.j != null || f();
    }

    public final boolean f() {
        BadgeState$State badgeState$State = this.e.b;
        return badgeState$State.j == null && badgeState$State.k != -1;
    }

    public final void g() {
        Context context = (Context) this.a.get();
        if (context == null) {
            return;
        }
        boolean zE = e();
        b bVar = this.e;
        this.b.setShapeAppearanceModel(j.a(context, zE ? bVar.b.g.intValue() : bVar.b.e.intValue(), e() ? bVar.b.h.intValue() : bVar.b.f.intValue(), new com.google.android.material.shape.a(0)).a());
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getAlpha() {
        return this.e.b.i;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicHeight() {
        return this.d.height();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicWidth() {
        return this.d.width();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        return -3;
    }

    public final void h(View view, FrameLayout frameLayout) {
        this.l = new WeakReference(view);
        this.m = new WeakReference(frameLayout);
        ViewGroup viewGroup = (ViewGroup) view.getParent();
        viewGroup.setClipChildren(false);
        viewGroup.setClipToPadding(false);
        i();
        invalidateSelf();
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x0220  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0238  */
    /* JADX WARN: Removed duplicated region for block: B:105:0x0241  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0259  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x025e  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x026b  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0278  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0285  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i() {
        /*
            Method dump skipped, instructions count: 736
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.badge.a.i():void");
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean isStateful() {
        return false;
    }

    @Override // android.graphics.drawable.Drawable, com.google.android.material.internal.m
    public final boolean onStateChange(int[] iArr) {
        return super.onStateChange(iArr);
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        b bVar = this.e;
        bVar.a.i = i;
        bVar.b.i = i;
        this.c.a.setAlpha(getAlpha());
        invalidateSelf();
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
    }
}
