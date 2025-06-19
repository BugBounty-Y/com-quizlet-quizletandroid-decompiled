package androidx.vectordrawable.graphics.drawable;

import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import androidx.collection.C0208f;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.ArrayDeque;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* loaded from: classes.dex */
public final class p extends g {
    public static final PorterDuff.Mode j = PorterDuff.Mode.SRC_IN;
    public n b;
    public PorterDuffColorFilter c;
    public ColorFilter d;
    public boolean e;
    public boolean f;
    public final float[] g;
    public final Matrix h;
    public final Rect i;

    public p() {
        this.f = true;
        this.g = new float[9];
        this.h = new Matrix();
        this.i = new Rect();
        n nVar = new n();
        nVar.c = null;
        nVar.d = j;
        nVar.b = new m();
        this.b = nVar;
    }

    public final PorterDuffColorFilter a(ColorStateList colorStateList, PorterDuff.Mode mode) {
        if (colorStateList == null || mode == null) {
            return null;
        }
        return new PorterDuffColorFilter(colorStateList.getColorForState(getState(), 0), mode);
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean canApplyTheme() {
        Drawable drawable = this.a;
        if (drawable == null) {
            return false;
        }
        drawable.canApplyTheme();
        return false;
    }

    @Override // android.graphics.drawable.Drawable
    public final void draw(Canvas canvas) {
        Paint paint;
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.draw(canvas);
            return;
        }
        Rect rect = this.i;
        copyBounds(rect);
        if (rect.width() <= 0 || rect.height() <= 0) {
            return;
        }
        ColorFilter colorFilter = this.d;
        if (colorFilter == null) {
            colorFilter = this.c;
        }
        Matrix matrix = this.h;
        canvas.getMatrix(matrix);
        float[] fArr = this.g;
        matrix.getValues(fArr);
        float fAbs = Math.abs(fArr[0]);
        float fAbs2 = Math.abs(fArr[4]);
        float fAbs3 = Math.abs(fArr[1]);
        float fAbs4 = Math.abs(fArr[3]);
        if (fAbs3 != DefinitionKt.NO_Float_VALUE || fAbs4 != DefinitionKt.NO_Float_VALUE) {
            fAbs = 1.0f;
            fAbs2 = 1.0f;
        }
        int iWidth = (int) (rect.width() * fAbs);
        int iMin = Math.min(2048, iWidth);
        int iMin2 = Math.min(2048, (int) (rect.height() * fAbs2));
        if (iMin <= 0 || iMin2 <= 0) {
            return;
        }
        int iSave = canvas.save();
        canvas.translate(rect.left, rect.top);
        if (isAutoMirrored() && getLayoutDirection() == 1) {
            canvas.translate(rect.width(), DefinitionKt.NO_Float_VALUE);
            canvas.scale(-1.0f, 1.0f);
        }
        rect.offsetTo(0, 0);
        n nVar = this.b;
        Bitmap bitmap = nVar.f;
        if (bitmap == null || iMin != bitmap.getWidth() || iMin2 != nVar.f.getHeight()) {
            nVar.f = Bitmap.createBitmap(iMin, iMin2, Bitmap.Config.ARGB_8888);
            nVar.k = true;
        }
        if (this.f) {
            n nVar2 = this.b;
            if (nVar2.k || nVar2.g != nVar2.c || nVar2.h != nVar2.d || nVar2.j != nVar2.e || nVar2.i != nVar2.b.getRootAlpha()) {
                n nVar3 = this.b;
                nVar3.f.eraseColor(0);
                Canvas canvas2 = new Canvas(nVar3.f);
                m mVar = nVar3.b;
                mVar.a(mVar.g, m.p, canvas2, iMin, iMin2);
                n nVar4 = this.b;
                nVar4.g = nVar4.c;
                nVar4.h = nVar4.d;
                nVar4.i = nVar4.b.getRootAlpha();
                nVar4.j = nVar4.e;
                nVar4.k = false;
            }
        } else {
            n nVar5 = this.b;
            nVar5.f.eraseColor(0);
            Canvas canvas3 = new Canvas(nVar5.f);
            m mVar2 = nVar5.b;
            mVar2.a(mVar2.g, m.p, canvas3, iMin, iMin2);
        }
        n nVar6 = this.b;
        if (nVar6.b.getRootAlpha() >= 255 && colorFilter == null) {
            paint = null;
        } else {
            if (nVar6.l == null) {
                Paint paint2 = new Paint();
                nVar6.l = paint2;
                paint2.setFilterBitmap(true);
            }
            nVar6.l.setAlpha(nVar6.b.getRootAlpha());
            nVar6.l.setColorFilter(colorFilter);
            paint = nVar6.l;
        }
        canvas.drawBitmap(nVar6.f, (Rect) null, rect, paint);
        canvas.restoreToCount(iSave);
    }

    @Override // android.graphics.drawable.Drawable
    public final int getAlpha() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.getAlpha() : this.b.b.getRootAlpha();
    }

    @Override // android.graphics.drawable.Drawable
    public final int getChangingConfigurations() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.getChangingConfigurations() : super.getChangingConfigurations() | this.b.getChangingConfigurations();
    }

    @Override // android.graphics.drawable.Drawable
    public final ColorFilter getColorFilter() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.getColorFilter() : this.d;
    }

    @Override // android.graphics.drawable.Drawable
    public final Drawable.ConstantState getConstantState() {
        if (this.a != null) {
            return new o(this.a.getConstantState());
        }
        this.b.a = getChangingConfigurations();
        return this.b;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicHeight() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.getIntrinsicHeight() : (int) this.b.b.i;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getIntrinsicWidth() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.getIntrinsicWidth() : (int) this.b.b.h;
    }

    @Override // android.graphics.drawable.Drawable
    public final int getOpacity() {
        Drawable drawable = this.a;
        if (drawable != null) {
            return drawable.getOpacity();
        }
        return -3;
    }

    @Override // android.graphics.drawable.Drawable
    public final void inflate(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet) throws XmlPullParserException, IOException {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.inflate(resources, xmlPullParser, attributeSet);
        } else {
            inflate(resources, xmlPullParser, attributeSet, null);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void invalidateSelf() {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.invalidateSelf();
        } else {
            super.invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean isAutoMirrored() {
        Drawable drawable = this.a;
        return drawable != null ? drawable.isAutoMirrored() : this.b.e;
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean isStateful() {
        Drawable drawable = this.a;
        if (drawable != null) {
            return drawable.isStateful();
        }
        if (super.isStateful()) {
            return true;
        }
        n nVar = this.b;
        if (nVar == null) {
            return false;
        }
        m mVar = nVar.b;
        if (mVar.n == null) {
            mVar.n = Boolean.valueOf(mVar.g.a());
        }
        if (mVar.n.booleanValue()) {
            return true;
        }
        ColorStateList colorStateList = this.b.c;
        return colorStateList != null && colorStateList.isStateful();
    }

    @Override // android.graphics.drawable.Drawable
    public final Drawable mutate() {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.mutate();
            return this;
        }
        if (!this.e && super.mutate() == this) {
            n nVar = this.b;
            n nVar2 = new n();
            nVar2.c = null;
            nVar2.d = j;
            if (nVar != null) {
                nVar2.a = nVar.a;
                m mVar = new m(nVar.b);
                nVar2.b = mVar;
                if (nVar.b.e != null) {
                    mVar.e = new Paint(nVar.b.e);
                }
                if (nVar.b.d != null) {
                    nVar2.b.d = new Paint(nVar.b.d);
                }
                nVar2.c = nVar.c;
                nVar2.d = nVar.d;
                nVar2.e = nVar.e;
            }
            this.b = nVar2;
            this.e = true;
        }
        return this;
    }

    @Override // android.graphics.drawable.Drawable
    public final void onBoundsChange(Rect rect) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setBounds(rect);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean onStateChange(int[] iArr) {
        boolean z;
        PorterDuff.Mode mode;
        Drawable drawable = this.a;
        if (drawable != null) {
            return drawable.setState(iArr);
        }
        n nVar = this.b;
        ColorStateList colorStateList = nVar.c;
        if (colorStateList == null || (mode = nVar.d) == null) {
            z = false;
        } else {
            this.c = a(colorStateList, mode);
            invalidateSelf();
            z = true;
        }
        m mVar = nVar.b;
        if (mVar.n == null) {
            mVar.n = Boolean.valueOf(mVar.g.a());
        }
        if (mVar.n.booleanValue()) {
            boolean zB = nVar.b.g.b(iArr);
            nVar.k |= zB;
            if (zB) {
                invalidateSelf();
                return true;
            }
        }
        return z;
    }

    @Override // android.graphics.drawable.Drawable
    public final void scheduleSelf(Runnable runnable, long j2) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.scheduleSelf(runnable, j2);
        } else {
            super.scheduleSelf(runnable, j2);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAlpha(int i) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setAlpha(i);
        } else if (this.b.b.getRootAlpha() != i) {
            this.b.b.setRootAlpha(i);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setAutoMirrored(boolean z) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setAutoMirrored(z);
        } else {
            this.b.e = z;
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setColorFilter(ColorFilter colorFilter) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setColorFilter(colorFilter);
        } else {
            this.d = colorFilter;
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setTint(int i) {
        Drawable drawable = this.a;
        if (drawable != null) {
            AbstractC3179j6.d(drawable, i);
        } else {
            setTintList(ColorStateList.valueOf(i));
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setTintList(ColorStateList colorStateList) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setTintList(colorStateList);
            return;
        }
        n nVar = this.b;
        if (nVar.c != colorStateList) {
            nVar.c = colorStateList;
            this.c = a(colorStateList, nVar.d);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void setTintMode(PorterDuff.Mode mode) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.setTintMode(mode);
            return;
        }
        n nVar = this.b;
        if (nVar.d != mode) {
            nVar.d = mode;
            this.c = a(nVar.c, mode);
            invalidateSelf();
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final boolean setVisible(boolean z, boolean z2) {
        Drawable drawable = this.a;
        return drawable != null ? drawable.setVisible(z, z2) : super.setVisible(z, z2);
    }

    @Override // android.graphics.drawable.Drawable
    public final void unscheduleSelf(Runnable runnable) {
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.unscheduleSelf(runnable);
        } else {
            super.unscheduleSelf(runnable);
        }
    }

    @Override // android.graphics.drawable.Drawable
    public final void inflate(Resources resources, XmlPullParser xmlPullParser, AttributeSet attributeSet, Resources.Theme theme) throws XmlPullParserException, IOException {
        m mVar;
        boolean z;
        int i;
        int i2;
        int i3;
        char c;
        int i4;
        Paint.Cap cap;
        Paint.Join join;
        Resources resources2 = resources;
        Drawable drawable = this.a;
        if (drawable != null) {
            drawable.inflate(resources2, xmlPullParser, attributeSet, theme);
            return;
        }
        n nVar = this.b;
        nVar.b = new m();
        TypedArray typedArrayH = androidx.core.content.res.b.h(resources2, theme, attributeSet, a.a);
        n nVar2 = this.b;
        m mVar2 = nVar2.b;
        int i5 = !androidx.core.content.res.b.e(xmlPullParser, "tintMode") ? -1 : typedArrayH.getInt(6, -1);
        PorterDuff.Mode mode = PorterDuff.Mode.SRC_IN;
        int i6 = 3;
        if (i5 == 3) {
            mode = PorterDuff.Mode.SRC_OVER;
        } else if (i5 != 5) {
            if (i5 != 9) {
                switch (i5) {
                    case 14:
                        mode = PorterDuff.Mode.MULTIPLY;
                        break;
                    case 15:
                        mode = PorterDuff.Mode.SCREEN;
                        break;
                    case 16:
                        mode = PorterDuff.Mode.ADD;
                        break;
                }
            } else {
                mode = PorterDuff.Mode.SRC_ATOP;
            }
        }
        nVar2.d = mode;
        ColorStateList colorStateListC = androidx.core.content.res.b.c(typedArrayH, xmlPullParser, theme);
        if (colorStateListC != null) {
            nVar2.c = colorStateListC;
        }
        boolean z2 = nVar2.e;
        if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "autoMirrored") != null) {
            z2 = typedArrayH.getBoolean(5, z2);
        }
        nVar2.e = z2;
        float f = mVar2.j;
        boolean z3 = false;
        int i7 = 1;
        if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "viewportWidth") != null) {
            f = typedArrayH.getFloat(7, f);
        }
        mVar2.j = f;
        float f2 = mVar2.k;
        if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "viewportHeight") != null) {
            f2 = typedArrayH.getFloat(8, f2);
        }
        mVar2.k = f2;
        if (mVar2.j <= DefinitionKt.NO_Float_VALUE) {
            throw new XmlPullParserException(typedArrayH.getPositionDescription() + "<vector> tag requires viewportWidth > 0");
        }
        if (f2 > DefinitionKt.NO_Float_VALUE) {
            mVar2.h = typedArrayH.getDimension(3, mVar2.h);
            int i8 = 2;
            float dimension = typedArrayH.getDimension(2, mVar2.i);
            mVar2.i = dimension;
            if (mVar2.h <= DefinitionKt.NO_Float_VALUE) {
                throw new XmlPullParserException(typedArrayH.getPositionDescription() + "<vector> tag requires width > 0");
            }
            if (dimension > DefinitionKt.NO_Float_VALUE) {
                float alpha = mVar2.getAlpha();
                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "alpha") != null) {
                    alpha = typedArrayH.getFloat(4, alpha);
                }
                mVar2.setAlpha(alpha);
                String string = typedArrayH.getString(0);
                if (string != null) {
                    mVar2.m = string;
                    mVar2.o.put(string, mVar2);
                }
                typedArrayH.recycle();
                nVar.a = getChangingConfigurations();
                nVar.k = true;
                n nVar3 = this.b;
                m mVar3 = nVar3.b;
                ArrayDeque arrayDeque = new ArrayDeque();
                arrayDeque.push(mVar3.g);
                int eventType = xmlPullParser.getEventType();
                int depth = xmlPullParser.getDepth() + 1;
                boolean z4 = true;
                while (eventType != i7 && (xmlPullParser.getDepth() >= depth || eventType != i6)) {
                    if (eventType == i8) {
                        String name = xmlPullParser.getName();
                        j jVar = (j) arrayDeque.peek();
                        boolean zEquals = "path".equals(name);
                        C0208f c0208f = mVar3.o;
                        mVar = mVar3;
                        if (zEquals) {
                            i iVar = new i();
                            iVar.e = DefinitionKt.NO_Float_VALUE;
                            iVar.g = 1.0f;
                            iVar.h = 1.0f;
                            i = depth;
                            iVar.i = DefinitionKt.NO_Float_VALUE;
                            iVar.j = 1.0f;
                            iVar.k = DefinitionKt.NO_Float_VALUE;
                            Paint.Cap cap2 = Paint.Cap.BUTT;
                            iVar.l = cap2;
                            Paint.Join join2 = Paint.Join.MITER;
                            iVar.m = join2;
                            iVar.n = 4.0f;
                            TypedArray typedArrayH2 = androidx.core.content.res.b.h(resources2, theme, attributeSet, a.c);
                            if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "pathData") != null) {
                                String string2 = typedArrayH2.getString(0);
                                if (string2 != null) {
                                    iVar.b = string2;
                                }
                                String string3 = typedArrayH2.getString(2);
                                if (string3 != null) {
                                    iVar.a = AbstractC3152g6.d(string3);
                                }
                                iVar.f = androidx.core.content.res.b.d(typedArrayH2, xmlPullParser, theme, "fillColor", 1);
                                float f3 = iVar.h;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "fillAlpha") != null) {
                                    f3 = typedArrayH2.getFloat(12, f3);
                                }
                                iVar.h = f3;
                                int i9 = xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "strokeLineCap") != null ? typedArrayH2.getInt(8, -1) : -1;
                                Paint.Cap cap3 = iVar.l;
                                if (i9 == 0) {
                                    cap = cap2;
                                } else if (i9 != 1) {
                                    cap = i9 != 2 ? cap3 : Paint.Cap.SQUARE;
                                } else {
                                    cap = Paint.Cap.ROUND;
                                }
                                iVar.l = cap;
                                int i10 = xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "strokeLineJoin") != null ? typedArrayH2.getInt(9, -1) : -1;
                                Paint.Join join3 = iVar.m;
                                if (i10 == 0) {
                                    join = join2;
                                } else if (i10 != 1) {
                                    join = i10 != 2 ? join3 : Paint.Join.BEVEL;
                                } else {
                                    join = Paint.Join.ROUND;
                                }
                                iVar.m = join;
                                float f4 = iVar.n;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "strokeMiterLimit") != null) {
                                    f4 = typedArrayH2.getFloat(10, f4);
                                }
                                iVar.n = f4;
                                iVar.d = androidx.core.content.res.b.d(typedArrayH2, xmlPullParser, theme, "strokeColor", 3);
                                float f5 = iVar.g;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "strokeAlpha") != null) {
                                    f5 = typedArrayH2.getFloat(11, f5);
                                }
                                iVar.g = f5;
                                float f6 = iVar.e;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "strokeWidth") != null) {
                                    f6 = typedArrayH2.getFloat(4, f6);
                                }
                                iVar.e = f6;
                                float f7 = iVar.j;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "trimPathEnd") != null) {
                                    f7 = typedArrayH2.getFloat(6, f7);
                                }
                                iVar.j = f7;
                                float f8 = iVar.k;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "trimPathOffset") != null) {
                                    f8 = typedArrayH2.getFloat(7, f8);
                                }
                                iVar.k = f8;
                                float f9 = iVar.i;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "trimPathStart") != null) {
                                    f9 = typedArrayH2.getFloat(5, f9);
                                }
                                iVar.i = f9;
                                int i11 = iVar.c;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "fillType") != null) {
                                    i11 = typedArrayH2.getInt(13, i11);
                                }
                                iVar.c = i11;
                            }
                            typedArrayH2.recycle();
                            jVar.b.add(iVar);
                            if (iVar.getPathName() != null) {
                                c0208f.put(iVar.getPathName(), iVar);
                            }
                            nVar3.a = nVar3.a;
                            z = false;
                            c = 5;
                            i4 = 1;
                            z4 = false;
                        } else {
                            i = depth;
                            if ("clip-path".equals(name)) {
                                h hVar = new h();
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "pathData") != null) {
                                    TypedArray typedArrayH3 = androidx.core.content.res.b.h(resources2, theme, attributeSet, a.d);
                                    String string4 = typedArrayH3.getString(0);
                                    if (string4 != null) {
                                        hVar.b = string4;
                                    }
                                    String string5 = typedArrayH3.getString(1);
                                    if (string5 != null) {
                                        hVar.a = AbstractC3152g6.d(string5);
                                    }
                                    hVar.c = !androidx.core.content.res.b.e(xmlPullParser, "fillType") ? 0 : typedArrayH3.getInt(2, 0);
                                    typedArrayH3.recycle();
                                }
                                jVar.b.add(hVar);
                                if (hVar.getPathName() != null) {
                                    c0208f.put(hVar.getPathName(), hVar);
                                }
                                nVar3.a = nVar3.a;
                            } else if (DBGroup.TABLE_NAME.equals(name)) {
                                j jVar2 = new j();
                                TypedArray typedArrayH4 = androidx.core.content.res.b.h(resources2, theme, attributeSet, a.b);
                                float f10 = jVar2.c;
                                if (androidx.core.content.res.b.e(xmlPullParser, "rotation")) {
                                    c = 5;
                                    f10 = typedArrayH4.getFloat(5, f10);
                                } else {
                                    c = 5;
                                }
                                jVar2.c = f10;
                                i4 = 1;
                                jVar2.d = typedArrayH4.getFloat(1, jVar2.d);
                                jVar2.e = typedArrayH4.getFloat(2, jVar2.e);
                                float f11 = jVar2.f;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "scaleX") != null) {
                                    f11 = typedArrayH4.getFloat(3, f11);
                                }
                                jVar2.f = f11;
                                float f12 = jVar2.g;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "scaleY") != null) {
                                    f12 = typedArrayH4.getFloat(4, f12);
                                }
                                jVar2.g = f12;
                                float f13 = jVar2.h;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "translateX") != null) {
                                    f13 = typedArrayH4.getFloat(6, f13);
                                }
                                jVar2.h = f13;
                                float f14 = jVar2.i;
                                if (xmlPullParser.getAttributeValue("http://schemas.android.com/apk/res/android", "translateY") != null) {
                                    f14 = typedArrayH4.getFloat(7, f14);
                                }
                                jVar2.i = f14;
                                z = false;
                                String string6 = typedArrayH4.getString(0);
                                if (string6 != null) {
                                    jVar2.k = string6;
                                }
                                jVar2.c();
                                typedArrayH4.recycle();
                                jVar.b.add(jVar2);
                                arrayDeque.push(jVar2);
                                if (jVar2.getGroupName() != null) {
                                    c0208f.put(jVar2.getGroupName(), jVar2);
                                }
                                nVar3.a = nVar3.a;
                            }
                            z = false;
                            c = 5;
                            i4 = 1;
                        }
                        i3 = i4;
                        i2 = 3;
                    } else {
                        mVar = mVar3;
                        z = z3;
                        i = depth;
                        i2 = i6;
                        i3 = 1;
                        if (eventType == i2 && DBGroup.TABLE_NAME.equals(xmlPullParser.getName())) {
                            arrayDeque.pop();
                        }
                    }
                    eventType = xmlPullParser.next();
                    z3 = z;
                    i6 = i2;
                    i7 = i3;
                    mVar3 = mVar;
                    depth = i;
                    i8 = 2;
                    resources2 = resources;
                }
                if (!z4) {
                    this.c = a(nVar.c, nVar.d);
                    return;
                }
                throw new XmlPullParserException("no path defined");
            }
            throw new XmlPullParserException(typedArrayH.getPositionDescription() + "<vector> tag requires height > 0");
        }
        throw new XmlPullParserException(typedArrayH.getPositionDescription() + "<vector> tag requires viewportHeight > 0");
    }

    public p(n nVar) {
        this.f = true;
        this.g = new float[9];
        this.h = new Matrix();
        this.i = new Rect();
        this.b = nVar;
        this.c = a(nVar.c, nVar.d);
    }
}
