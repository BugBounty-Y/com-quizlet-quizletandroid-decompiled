package com.google.android.material.internal;

import android.animation.TimeInterpolator;
import android.content.res.ColorStateList;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.os.Build;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.Gravity;
import android.view.ViewGroup;
import android.view.animation.BaseInterpolator;
import androidx.appcompat.app.Q;
import androidx.core.view.V;
import com.comscore.streaming.ContentType;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3454f4;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class b {
    public Typeface A;
    public Typeface B;
    public Typeface C;
    public com.google.android.material.resources.b D;
    public com.google.android.material.resources.b E;
    public CharSequence G;
    public CharSequence H;
    public boolean I;
    public Bitmap K;
    public float L;
    public float M;
    public float N;
    public float O;
    public float P;
    public int Q;
    public int[] R;
    public boolean S;
    public final TextPaint T;
    public final TextPaint U;
    public TimeInterpolator V;
    public BaseInterpolator W;
    public float X;
    public float Y;
    public float Z;
    public final ViewGroup a;
    public ColorStateList a0;
    public float b;
    public float b0;
    public boolean c;
    public float c0;
    public float d;
    public float d0;
    public float e;
    public ColorStateList e0;
    public int f;
    public float f0;
    public final Rect g;
    public float g0;
    public final Rect h;
    public float h0;
    public final RectF i;
    public StaticLayout i0;
    public float j0;
    public float k0;
    public float l0;
    public CharSequence m0;
    public ColorStateList n;
    public ColorStateList o;
    public int p;
    public float q;
    public float r;
    public float s;
    public float t;
    public float u;
    public float v;
    public Typeface w;
    public Typeface x;
    public Typeface y;
    public Typeface z;
    public int j = 16;
    public int k = 16;
    public float l = 15.0f;
    public float m = 15.0f;
    public TextUtils.TruncateAt F = TextUtils.TruncateAt.END;
    public boolean J = true;
    public int n0 = 1;
    public float o0 = DefinitionKt.NO_Float_VALUE;
    public float p0 = 1.0f;
    public int q0 = 1;

    public b(ViewGroup viewGroup) {
        this.a = viewGroup;
        TextPaint textPaint = new TextPaint(129);
        this.T = textPaint;
        this.U = new TextPaint(textPaint);
        this.h = new Rect();
        this.g = new Rect();
        this.i = new RectF();
        float f = this.d;
        this.e = android.support.v4.media.session.a.a(1.0f, f, 0.5f, f);
        h(viewGroup.getContext().getResources().getConfiguration());
    }

    public static int a(int i, float f, int i2) {
        float f2 = 1.0f - f;
        return Color.argb(Math.round((Color.alpha(i2) * f) + (Color.alpha(i) * f2)), Math.round((Color.red(i2) * f) + (Color.red(i) * f2)), Math.round((Color.green(i2) * f) + (Color.green(i) * f2)), Math.round((Color.blue(i2) * f) + (Color.blue(i) * f2)));
    }

    public static float g(float f, float f2, float f3, TimeInterpolator timeInterpolator) {
        if (timeInterpolator != null) {
            f3 = timeInterpolator.getInterpolation(f3);
        }
        return com.google.android.material.animation.a.a(f, f2, f3);
    }

    public final boolean b(CharSequence charSequence) {
        WeakHashMap weakHashMap = V.a;
        boolean z = this.a.getLayoutDirection() == 1;
        if (this.J) {
            return (z ? androidx.core.text.f.d : androidx.core.text.f.c).t(charSequence, 0, charSequence.length());
        }
        return z;
    }

    public final void c(float f, boolean z) {
        float f2;
        float f3;
        Typeface typeface;
        boolean z2;
        Layout.Alignment alignment;
        if (this.G == null) {
            return;
        }
        float fWidth = this.h.width();
        float fWidth2 = this.g.width();
        if (Math.abs(f - 1.0f) < 1.0E-5f) {
            f2 = this.m;
            f3 = this.f0;
            this.L = 1.0f;
            typeface = this.w;
        } else {
            float f4 = this.l;
            float f5 = this.g0;
            Typeface typeface2 = this.z;
            if (Math.abs(f - DefinitionKt.NO_Float_VALUE) < 1.0E-5f) {
                this.L = 1.0f;
            } else {
                this.L = g(this.l, this.m, f, this.W) / this.l;
            }
            float f6 = this.m / this.l;
            fWidth = (z || this.c || fWidth2 * f6 <= fWidth) ? fWidth2 : Math.min(fWidth / f6, fWidth2);
            f2 = f4;
            f3 = f5;
            typeface = typeface2;
        }
        TextPaint textPaint = this.T;
        if (fWidth > DefinitionKt.NO_Float_VALUE) {
            boolean z3 = this.M != f2;
            boolean z4 = this.h0 != f3;
            boolean z5 = this.C != typeface;
            StaticLayout staticLayout = this.i0;
            boolean z6 = z3 || z4 || (staticLayout != null && (fWidth > ((float) staticLayout.getWidth()) ? 1 : (fWidth == ((float) staticLayout.getWidth()) ? 0 : -1)) != 0) || z5 || this.S;
            this.M = f2;
            this.h0 = f3;
            this.C = typeface;
            this.S = false;
            textPaint.setLinearText(this.L != 1.0f);
            z2 = z6;
        } else {
            z2 = false;
        }
        if (this.H == null || z2) {
            textPaint.setTextSize(this.M);
            textPaint.setTypeface(this.C);
            textPaint.setLetterSpacing(this.h0);
            boolean zB = b(this.G);
            this.I = zB;
            int i = this.n0;
            if (i <= 1 || (zB && !this.c)) {
                i = 1;
            }
            if (i == 1) {
                alignment = Layout.Alignment.ALIGN_NORMAL;
            } else {
                int absoluteGravity = Gravity.getAbsoluteGravity(this.j, zB ? 1 : 0) & 7;
                alignment = absoluteGravity != 1 ? absoluteGravity != 5 ? this.I ? Layout.Alignment.ALIGN_OPPOSITE : Layout.Alignment.ALIGN_NORMAL : this.I ? Layout.Alignment.ALIGN_NORMAL : Layout.Alignment.ALIGN_OPPOSITE : Layout.Alignment.ALIGN_CENTER;
            }
            l lVar = new l(this.G, textPaint, (int) fWidth);
            lVar.l = this.F;
            lVar.k = zB;
            lVar.e = alignment;
            lVar.j = false;
            lVar.f = i;
            float f7 = this.o0;
            float f8 = this.p0;
            lVar.g = f7;
            lVar.h = f8;
            lVar.i = this.q0;
            StaticLayout staticLayoutA = lVar.a();
            staticLayoutA.getClass();
            this.i0 = staticLayoutA;
            this.H = staticLayoutA.getText();
        }
    }

    public final void d(Canvas canvas) {
        int iSave = canvas.save();
        if (this.H != null) {
            RectF rectF = this.i;
            if (rectF.width() <= DefinitionKt.NO_Float_VALUE || rectF.height() <= DefinitionKt.NO_Float_VALUE) {
                return;
            }
            TextPaint textPaint = this.T;
            textPaint.setTextSize(this.M);
            float f = this.u;
            float f2 = this.v;
            float f3 = this.L;
            if (f3 != 1.0f && !this.c) {
                canvas.scale(f3, f3, f, f2);
            }
            if (this.n0 <= 1 || ((this.I && !this.c) || (this.c && this.b <= this.e))) {
                canvas.translate(f, f2);
                this.i0.draw(canvas);
            } else {
                float lineStart = this.u - this.i0.getLineStart(0);
                int alpha = textPaint.getAlpha();
                canvas.translate(lineStart, f2);
                if (!this.c) {
                    textPaint.setAlpha((int) (this.l0 * alpha));
                    if (Build.VERSION.SDK_INT >= 31) {
                        float f4 = this.N;
                        float f5 = this.O;
                        float f6 = this.P;
                        int i = this.Q;
                        textPaint.setShadowLayer(f4, f5, f6, androidx.core.graphics.d.d(i, (Color.alpha(i) * textPaint.getAlpha()) / 255));
                    }
                    this.i0.draw(canvas);
                }
                if (!this.c) {
                    textPaint.setAlpha((int) (this.k0 * alpha));
                }
                int i2 = Build.VERSION.SDK_INT;
                if (i2 >= 31) {
                    float f7 = this.N;
                    float f8 = this.O;
                    float f9 = this.P;
                    int i3 = this.Q;
                    textPaint.setShadowLayer(f7, f8, f9, androidx.core.graphics.d.d(i3, (Color.alpha(i3) * textPaint.getAlpha()) / 255));
                }
                int lineBaseline = this.i0.getLineBaseline(0);
                CharSequence charSequence = this.m0;
                float f10 = lineBaseline;
                canvas.drawText(charSequence, 0, charSequence.length(), DefinitionKt.NO_Float_VALUE, f10, textPaint);
                if (i2 >= 31) {
                    textPaint.setShadowLayer(this.N, this.O, this.P, this.Q);
                }
                if (!this.c) {
                    String strTrim = this.m0.toString().trim();
                    if (strTrim.endsWith("…")) {
                        strTrim = strTrim.substring(0, strTrim.length() - 1);
                    }
                    String str = strTrim;
                    textPaint.setAlpha(alpha);
                    canvas.drawText(str, 0, Math.min(this.i0.getLineEnd(0), str.length()), DefinitionKt.NO_Float_VALUE, f10, (Paint) textPaint);
                }
                canvas = canvas;
            }
            canvas.restoreToCount(iSave);
        }
    }

    public final float e() {
        TextPaint textPaint = this.U;
        textPaint.setTextSize(this.m);
        textPaint.setTypeface(this.w);
        textPaint.setLetterSpacing(this.f0);
        return -textPaint.ascent();
    }

    public final int f(ColorStateList colorStateList) {
        if (colorStateList == null) {
            return 0;
        }
        int[] iArr = this.R;
        return iArr != null ? colorStateList.getColorForState(iArr, 0) : colorStateList.getDefaultColor();
    }

    public final void h(Configuration configuration) {
        if (Build.VERSION.SDK_INT >= 31) {
            Typeface typeface = this.y;
            if (typeface != null) {
                this.x = AbstractC3454f4.a(configuration, typeface);
            }
            Typeface typeface2 = this.B;
            if (typeface2 != null) {
                this.A = AbstractC3454f4.a(configuration, typeface2);
            }
            Typeface typeface3 = this.x;
            if (typeface3 == null) {
                typeface3 = this.y;
            }
            this.w = typeface3;
            Typeface typeface4 = this.A;
            if (typeface4 == null) {
                typeface4 = this.B;
            }
            this.z = typeface4;
            i(true);
        }
    }

    public final void i(boolean z) {
        float fMeasureText;
        float f;
        StaticLayout staticLayout;
        ViewGroup viewGroup = this.a;
        if ((viewGroup.getHeight() <= 0 || viewGroup.getWidth() <= 0) && !z) {
            return;
        }
        c(1.0f, z);
        CharSequence charSequence = this.H;
        TextPaint textPaint = this.T;
        if (charSequence != null && (staticLayout = this.i0) != null) {
            this.m0 = TextUtils.ellipsize(charSequence, textPaint, staticLayout.getWidth(), this.F);
        }
        CharSequence charSequence2 = this.m0;
        if (charSequence2 != null) {
            this.j0 = textPaint.measureText(charSequence2, 0, charSequence2.length());
        } else {
            this.j0 = DefinitionKt.NO_Float_VALUE;
        }
        int absoluteGravity = Gravity.getAbsoluteGravity(this.k, this.I ? 1 : 0);
        int i = absoluteGravity & ContentType.LONG_FORM_ON_DEMAND;
        Rect rect = this.h;
        if (i == 48) {
            this.r = rect.top;
        } else if (i != 80) {
            this.r = rect.centerY() - ((textPaint.descent() - textPaint.ascent()) / 2.0f);
        } else {
            this.r = textPaint.ascent() + rect.bottom;
        }
        int i2 = absoluteGravity & 8388615;
        if (i2 == 1) {
            this.t = rect.centerX() - (this.j0 / 2.0f);
        } else if (i2 != 5) {
            this.t = rect.left;
        } else {
            this.t = rect.right - this.j0;
        }
        c(DefinitionKt.NO_Float_VALUE, z);
        float height = this.i0 != null ? r1.getHeight() : 0.0f;
        StaticLayout staticLayout2 = this.i0;
        if (staticLayout2 == null || this.n0 <= 1) {
            CharSequence charSequence3 = this.H;
            fMeasureText = charSequence3 != null ? textPaint.measureText(charSequence3, 0, charSequence3.length()) : 0.0f;
        } else {
            fMeasureText = staticLayout2.getWidth();
        }
        StaticLayout staticLayout3 = this.i0;
        this.p = staticLayout3 != null ? staticLayout3.getLineCount() : 0;
        int absoluteGravity2 = Gravity.getAbsoluteGravity(this.j, this.I ? 1 : 0);
        int i3 = absoluteGravity2 & ContentType.LONG_FORM_ON_DEMAND;
        Rect rect2 = this.g;
        if (i3 == 48) {
            this.q = rect2.top;
        } else if (i3 != 80) {
            this.q = rect2.centerY() - (height / 2.0f);
        } else {
            this.q = textPaint.descent() + (rect2.bottom - height);
        }
        int i4 = absoluteGravity2 & 8388615;
        if (i4 == 1) {
            this.s = rect2.centerX() - (fMeasureText / 2.0f);
        } else if (i4 != 5) {
            this.s = rect2.left;
        } else {
            this.s = rect2.right - fMeasureText;
        }
        Bitmap bitmap = this.K;
        if (bitmap != null) {
            bitmap.recycle();
            this.K = null;
        }
        q(this.b);
        float f2 = this.b;
        boolean z2 = this.c;
        RectF rectF = this.i;
        if (z2) {
            if (f2 < this.e) {
                rect = rect2;
            }
            rectF.set(rect);
        } else {
            rectF.left = g(rect2.left, rect.left, f2, this.V);
            rectF.top = g(this.q, this.r, f2, this.V);
            rectF.right = g(rect2.right, rect.right, f2, this.V);
            rectF.bottom = g(rect2.bottom, rect.bottom, f2, this.V);
        }
        if (!this.c) {
            this.u = g(this.s, this.t, f2, this.V);
            this.v = g(this.q, this.r, f2, this.V);
            q(f2);
            f = f2;
        } else if (f2 < this.e) {
            this.u = this.s;
            this.v = this.q;
            q(DefinitionKt.NO_Float_VALUE);
            f = 0.0f;
        } else {
            this.u = this.t;
            this.v = this.r - Math.max(0, this.f);
            q(1.0f);
            f = 1.0f;
        }
        androidx.interpolator.view.animation.a aVar = com.google.android.material.animation.a.b;
        this.k0 = 1.0f - g(DefinitionKt.NO_Float_VALUE, 1.0f, 1.0f - f2, aVar);
        WeakHashMap weakHashMap = V.a;
        viewGroup.postInvalidateOnAnimation();
        this.l0 = g(1.0f, DefinitionKt.NO_Float_VALUE, f2, aVar);
        viewGroup.postInvalidateOnAnimation();
        ColorStateList colorStateList = this.o;
        ColorStateList colorStateList2 = this.n;
        if (colorStateList != colorStateList2) {
            textPaint.setColor(a(f(colorStateList2), f, f(this.o)));
        } else {
            textPaint.setColor(f(colorStateList));
        }
        int i5 = Build.VERSION.SDK_INT;
        float f3 = this.f0;
        float f4 = this.g0;
        if (f3 != f4) {
            textPaint.setLetterSpacing(g(f4, f3, f2, aVar));
        } else {
            textPaint.setLetterSpacing(f3);
        }
        this.N = com.google.android.material.animation.a.a(this.b0, this.X, f2);
        this.O = com.google.android.material.animation.a.a(this.c0, this.Y, f2);
        this.P = com.google.android.material.animation.a.a(this.d0, this.Z, f2);
        int iA = a(f(this.e0), f2, f(this.a0));
        this.Q = iA;
        textPaint.setShadowLayer(this.N, this.O, this.P, iA);
        if (this.c) {
            int alpha = textPaint.getAlpha();
            float f5 = this.e;
            textPaint.setAlpha((int) ((f2 <= f5 ? com.google.android.material.animation.a.b(1.0f, DefinitionKt.NO_Float_VALUE, this.d, f5, f2) : com.google.android.material.animation.a.b(DefinitionKt.NO_Float_VALUE, 1.0f, f5, 1.0f, f2)) * alpha));
            if (i5 >= 31) {
                float f6 = this.N;
                float f7 = this.O;
                float f8 = this.P;
                int i6 = this.Q;
                textPaint.setShadowLayer(f6, f7, f8, androidx.core.graphics.d.d(i6, (Color.alpha(i6) * textPaint.getAlpha()) / 255));
            }
        }
        viewGroup.postInvalidateOnAnimation();
    }

    public final void j(ColorStateList colorStateList) {
        if (this.o == colorStateList && this.n == colorStateList) {
            return;
        }
        this.o = colorStateList;
        this.n = colorStateList;
        i(false);
    }

    public final void k(int i) {
        ViewGroup viewGroup = this.a;
        com.google.android.material.resources.e eVar = new com.google.android.material.resources.e(viewGroup.getContext(), i);
        ColorStateList colorStateList = eVar.j;
        if (colorStateList != null) {
            this.o = colorStateList;
        }
        float f = eVar.k;
        if (f != DefinitionKt.NO_Float_VALUE) {
            this.m = f;
        }
        ColorStateList colorStateList2 = eVar.a;
        if (colorStateList2 != null) {
            this.a0 = colorStateList2;
        }
        this.Y = eVar.e;
        this.Z = eVar.f;
        this.X = eVar.g;
        this.f0 = eVar.i;
        com.google.android.material.resources.b bVar = this.E;
        if (bVar != null) {
            bVar.c = true;
        }
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(this, 23);
        eVar.a();
        this.E = new com.google.android.material.resources.b(aVar, eVar.n);
        eVar.c(viewGroup.getContext(), this.E);
        i(false);
    }

    public final void l(int i) {
        if (this.k != i) {
            this.k = i;
            i(false);
        }
    }

    public final boolean m(Typeface typeface) {
        com.google.android.material.resources.b bVar = this.E;
        if (bVar != null) {
            bVar.c = true;
        }
        if (this.y == typeface) {
            return false;
        }
        this.y = typeface;
        Typeface typefaceA = AbstractC3454f4.a(this.a.getContext().getResources().getConfiguration(), typeface);
        this.x = typefaceA;
        if (typefaceA == null) {
            typefaceA = this.y;
        }
        this.w = typefaceA;
        return true;
    }

    public final void n(int i) {
        ViewGroup viewGroup = this.a;
        com.google.android.material.resources.e eVar = new com.google.android.material.resources.e(viewGroup.getContext(), i);
        ColorStateList colorStateList = eVar.j;
        if (colorStateList != null) {
            this.n = colorStateList;
        }
        float f = eVar.k;
        if (f != DefinitionKt.NO_Float_VALUE) {
            this.l = f;
        }
        ColorStateList colorStateList2 = eVar.a;
        if (colorStateList2 != null) {
            this.e0 = colorStateList2;
        }
        this.c0 = eVar.e;
        this.d0 = eVar.f;
        this.b0 = eVar.g;
        this.g0 = eVar.i;
        com.google.android.material.resources.b bVar = this.D;
        if (bVar != null) {
            bVar.c = true;
        }
        Q q = new Q(this);
        eVar.a();
        this.D = new com.google.android.material.resources.b(q, eVar.n);
        eVar.c(viewGroup.getContext(), this.D);
        i(false);
    }

    public final boolean o(Typeface typeface) {
        com.google.android.material.resources.b bVar = this.D;
        if (bVar != null) {
            bVar.c = true;
        }
        if (this.B == typeface) {
            return false;
        }
        this.B = typeface;
        Typeface typefaceA = AbstractC3454f4.a(this.a.getContext().getResources().getConfiguration(), typeface);
        this.A = typefaceA;
        if (typefaceA == null) {
            typefaceA = this.B;
        }
        this.z = typefaceA;
        return true;
    }

    public final void p(float f) {
        float f2;
        if (f < DefinitionKt.NO_Float_VALUE) {
            f = 0.0f;
        } else if (f > 1.0f) {
            f = 1.0f;
        }
        if (f != this.b) {
            this.b = f;
            boolean z = this.c;
            RectF rectF = this.i;
            Rect rect = this.h;
            Rect rect2 = this.g;
            if (z) {
                if (f < this.e) {
                    rect = rect2;
                }
                rectF.set(rect);
            } else {
                rectF.left = g(rect2.left, rect.left, f, this.V);
                rectF.top = g(this.q, this.r, f, this.V);
                rectF.right = g(rect2.right, rect.right, f, this.V);
                rectF.bottom = g(rect2.bottom, rect.bottom, f, this.V);
            }
            if (!this.c) {
                this.u = g(this.s, this.t, f, this.V);
                this.v = g(this.q, this.r, f, this.V);
                q(f);
                f2 = f;
            } else if (f < this.e) {
                this.u = this.s;
                this.v = this.q;
                q(DefinitionKt.NO_Float_VALUE);
                f2 = 0.0f;
            } else {
                this.u = this.t;
                this.v = this.r - Math.max(0, this.f);
                q(1.0f);
                f2 = 1.0f;
            }
            androidx.interpolator.view.animation.a aVar = com.google.android.material.animation.a.b;
            this.k0 = 1.0f - g(DefinitionKt.NO_Float_VALUE, 1.0f, 1.0f - f, aVar);
            WeakHashMap weakHashMap = V.a;
            ViewGroup viewGroup = this.a;
            viewGroup.postInvalidateOnAnimation();
            this.l0 = g(1.0f, DefinitionKt.NO_Float_VALUE, f, aVar);
            viewGroup.postInvalidateOnAnimation();
            ColorStateList colorStateList = this.o;
            ColorStateList colorStateList2 = this.n;
            TextPaint textPaint = this.T;
            if (colorStateList != colorStateList2) {
                textPaint.setColor(a(f(colorStateList2), f2, f(this.o)));
            } else {
                textPaint.setColor(f(colorStateList));
            }
            int i = Build.VERSION.SDK_INT;
            float f3 = this.f0;
            float f4 = this.g0;
            if (f3 != f4) {
                textPaint.setLetterSpacing(g(f4, f3, f, aVar));
            } else {
                textPaint.setLetterSpacing(f3);
            }
            this.N = com.google.android.material.animation.a.a(this.b0, this.X, f);
            this.O = com.google.android.material.animation.a.a(this.c0, this.Y, f);
            this.P = com.google.android.material.animation.a.a(this.d0, this.Z, f);
            int iA = a(f(this.e0), f, f(this.a0));
            this.Q = iA;
            textPaint.setShadowLayer(this.N, this.O, this.P, iA);
            if (this.c) {
                int alpha = textPaint.getAlpha();
                float f5 = this.e;
                textPaint.setAlpha((int) ((f <= f5 ? com.google.android.material.animation.a.b(1.0f, DefinitionKt.NO_Float_VALUE, this.d, f5, f) : com.google.android.material.animation.a.b(DefinitionKt.NO_Float_VALUE, 1.0f, f5, 1.0f, f)) * alpha));
                if (i >= 31) {
                    float f6 = this.N;
                    float f7 = this.O;
                    float f8 = this.P;
                    int i2 = this.Q;
                    textPaint.setShadowLayer(f6, f7, f8, androidx.core.graphics.d.d(i2, (Color.alpha(i2) * textPaint.getAlpha()) / 255));
                }
            }
            viewGroup.postInvalidateOnAnimation();
        }
    }

    public final void q(float f) {
        c(f, false);
        WeakHashMap weakHashMap = V.a;
        this.a.postInvalidateOnAnimation();
    }
}
