package com.lyft.android.scissors;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.util.AttributeSet;
import android.view.MotionEvent;
import android.widget.ImageView;
import androidx.compose.animation.f0;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.concurrent.ExecutorService;

/* loaded from: classes2.dex */
public class CropView extends ImageView {
    public k a;
    public c b;
    public final Paint c;
    public final Paint d;
    public Bitmap e;
    public final Matrix f;
    public b g;
    public int h;
    public final Path i;
    public final RectF j;

    public CropView(Context context) {
        super(context);
        this.c = new Paint();
        this.d = new Paint();
        this.f = new Matrix();
        this.h = 0;
        this.i = new Path();
        this.j = new RectF();
        c(context, null);
    }

    public final void a(Canvas canvas) {
        Matrix matrix = this.f;
        matrix.reset();
        k kVar = this.a;
        matrix.postTranslate((-kVar.j) / 2.0f, (-kVar.k) / 2.0f);
        float f = kVar.n;
        matrix.postScale(f, f);
        f0 f0Var = kVar.o;
        matrix.postTranslate(f0Var.b, f0Var.c);
        canvas.drawBitmap(this.e, matrix, this.d);
    }

    public final void b(Canvas canvas) {
        k kVar = this.a;
        int i = kVar.h;
        int i2 = kVar.i;
        int width = (getWidth() - i) / 2;
        int height = (getHeight() - i2) / 2;
        float f = height;
        float height2 = getHeight() - height;
        Paint paint = this.c;
        canvas.drawRect(DefinitionKt.NO_Float_VALUE, f, width, height2, paint);
        canvas.drawRect(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, getWidth(), f, paint);
        canvas.drawRect(getWidth() - width, f, getWidth(), getHeight() - height, paint);
        canvas.drawRect(DefinitionKt.NO_Float_VALUE, getHeight() - height, getWidth(), getHeight(), paint);
    }

    public final void c(Context context, AttributeSet attributeSet) {
        c cVar = new c();
        float f = DefinitionKt.NO_Float_VALUE;
        cVar.a = DefinitionKt.NO_Float_VALUE;
        cVar.b = 10.0f;
        cVar.c = DefinitionKt.NO_Float_VALUE;
        cVar.d = 0;
        cVar.e = -939524096;
        cVar.f = 0;
        if (attributeSet != null) {
            TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, j.a);
            float f2 = typedArrayObtainStyledAttributes.getFloat(5, DefinitionKt.NO_Float_VALUE);
            if (f2 <= DefinitionKt.NO_Float_VALUE) {
                f2 = 0.0f;
            }
            cVar.a = f2;
            float f3 = typedArrayObtainStyledAttributes.getFloat(0, 10.0f);
            cVar.b = f3 > DefinitionKt.NO_Float_VALUE ? f3 : 10.0f;
            float f4 = typedArrayObtainStyledAttributes.getFloat(1, DefinitionKt.NO_Float_VALUE);
            if (f4 > DefinitionKt.NO_Float_VALUE) {
                f = f4;
            }
            cVar.c = f;
            cVar.e = typedArrayObtainStyledAttributes.getColor(3, -939524096);
            cVar.d = typedArrayObtainStyledAttributes.getDimensionPixelSize(4, 0);
            cVar.f = typedArrayObtainStyledAttributes.getInt(2, 0);
            typedArrayObtainStyledAttributes.recycle();
        }
        this.b = cVar;
        this.a = new k(cVar);
        this.d.setFilterBitmap(true);
        setViewportOverlayColor(this.b.e);
        int i = this.b.f;
        this.h = i;
        if (i != 0) {
            Paint paint = this.c;
            paint.setFlags(paint.getFlags() | 1);
        }
    }

    public final void d() {
        Bitmap bitmap = this.e;
        boolean z = bitmap == null;
        int width = z ? 0 : bitmap.getWidth();
        int height = z ? 0 : this.e.getHeight();
        k kVar = this.a;
        int width2 = getWidth();
        int height2 = getHeight();
        c cVar = kVar.a;
        kVar.g = cVar.a;
        kVar.f = new Rect(0, 0, width2 / 2, height2 / 2);
        float f = width;
        float f2 = height;
        float f3 = f / f2;
        float f4 = width2 / height2;
        float f5 = cVar.a;
        if (Float.compare(DefinitionKt.NO_Float_VALUE, f5) != 0) {
            f3 = f5;
        }
        if (f3 > f4) {
            int i = width2 - (cVar.d * 2);
            kVar.h = i;
            kVar.i = (int) ((1.0f / f3) * i);
        } else {
            int i2 = height2 - (cVar.d * 2);
            kVar.i = i2;
            kVar.h = (int) (i2 * f3);
        }
        kVar.j = width;
        kVar.k = height;
        if (width <= 0 || height <= 0) {
            return;
        }
        float fMax = Math.max(kVar.h / f, kVar.i / f2);
        kVar.d = fMax;
        kVar.n = Math.max(kVar.n, fMax);
        kVar.b();
        Rect rect = kVar.f;
        float f6 = rect.right;
        float f7 = rect.bottom;
        f0 f0Var = kVar.o;
        f0Var.b = f6;
        f0Var.c = f7;
        kVar.a();
    }

    @Override // android.view.View
    public final boolean dispatchTouchEvent(MotionEvent motionEvent) {
        f0 f0Var;
        f0 f0Var2;
        boolean zDispatchTouchEvent = super.dispatchTouchEvent(motionEvent);
        if (!isEnabled()) {
            return zDispatchTouchEvent;
        }
        k kVar = this.a;
        kVar.getClass();
        int actionIndex = motionEvent.getActionIndex();
        if (actionIndex < 2) {
            int actionMasked = motionEvent.getActionMasked();
            boolean z = actionMasked == 6 || actionMasked == 1;
            f0[] f0VarArr = kVar.b;
            f0[] f0VarArr2 = kVar.c;
            if (z) {
                f0VarArr2[actionIndex] = null;
                f0VarArr[actionIndex] = null;
            } else {
                for (int i = 0; i < 2; i++) {
                    if (i < motionEvent.getPointerCount()) {
                        float x = motionEvent.getX(i);
                        float y = motionEvent.getY(i);
                        if (f0VarArr[i] == null) {
                            f0VarArr[i] = new f0(x, y);
                            f0VarArr2[i] = null;
                        } else {
                            if (f0VarArr2[i] == null) {
                                f0VarArr2[i] = new f0(5);
                            }
                            f0 f0Var3 = f0VarArr2[i];
                            f0 f0Var4 = f0VarArr[i];
                            f0Var3.getClass();
                            f0Var3.b = f0Var4.b;
                            f0Var3.c = f0Var4.c;
                            f0 f0Var5 = f0VarArr[i];
                            f0Var5.b = x;
                            f0Var5.c = y;
                        }
                    } else {
                        f0VarArr2[i] = null;
                        f0VarArr[i] = null;
                    }
                }
            }
            int i2 = 0;
            for (f0 f0Var6 : f0VarArr) {
                if (f0Var6 != null) {
                    i2++;
                }
            }
            if (i2 == 1) {
                f0 f0Var7 = f0VarArr[0];
                if (f0Var7 != null) {
                    f0 f0Var8 = f0VarArr2[0];
                    if (f0Var8 == null) {
                        f0Var8 = f0Var7;
                    }
                    f0Var2 = f0.d(f0Var7, f0Var8);
                } else {
                    f0Var2 = new f0(5);
                }
                f0 f0Var9 = kVar.o;
                f0Var9.b += f0Var2.b;
                f0Var9.c += f0Var2.c;
            }
            int i3 = 0;
            for (f0 f0Var10 : f0VarArr) {
                if (f0Var10 != null) {
                    i3++;
                }
            }
            if (i3 == 2) {
                f0 f0VarD = f0.d(f0VarArr[1], f0VarArr[0]);
                f0 f0Var11 = f0VarArr2[0];
                f0 f0VarD2 = (f0Var11 == null || (f0Var = f0VarArr2[1]) == null) ? f0.d(f0VarArr[1], f0VarArr[0]) : f0.d(f0Var, f0Var11);
                float f = f0VarD.b;
                float f2 = f0VarD.c;
                float fSqrt = (float) Math.sqrt((f2 * f2) + (f * f));
                float f3 = f0VarD2.b;
                float f4 = f0VarD2.c;
                float fSqrt2 = (float) Math.sqrt((f4 * f4) + (f3 * f3));
                float f5 = kVar.n;
                if (fSqrt2 != DefinitionKt.NO_Float_VALUE) {
                    f5 *= fSqrt / fSqrt2;
                }
                float f6 = kVar.d;
                if (f5 < f6) {
                    f5 = f6;
                }
                float f7 = kVar.e;
                if (f5 > f7) {
                    f5 = f7;
                }
                kVar.n = f5;
                kVar.b();
            }
            int actionMasked2 = motionEvent.getActionMasked();
            if (actionMasked2 == 6 || actionMasked2 == 1) {
                kVar.a();
            }
        }
        invalidate();
        return true;
    }

    public Bitmap getImageBitmap() {
        return this.e;
    }

    public float getImageRatio() {
        return getImageBitmap() != null ? r0.getWidth() / r0.getHeight() : DefinitionKt.NO_Float_VALUE;
    }

    public int getViewportHeight() {
        return this.a.i;
    }

    public float getViewportRatio() {
        return this.a.g;
    }

    public int getViewportWidth() {
        return this.a.h;
    }

    @Override // android.widget.ImageView, android.view.View
    public final void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (this.e == null) {
            return;
        }
        a(canvas);
        if (this.h == 0) {
            b(canvas);
            return;
        }
        k kVar = this.a;
        int i = kVar.h;
        int i2 = kVar.i;
        int width = (getWidth() - i) / 2;
        int height = (getHeight() - i2) / 2;
        int width2 = getWidth() - width;
        int height2 = getHeight() - height;
        RectF rectF = this.j;
        float f = width;
        rectF.left = f;
        float f2 = height;
        rectF.top = f2;
        float f3 = width2;
        rectF.right = f3;
        float f4 = height2;
        rectF.bottom = f4;
        Path path = this.i;
        path.reset();
        path.moveTo(f, getHeight() / 2);
        path.arcTo(rectF, 180.0f, 90.0f, false);
        path.lineTo(f, f2);
        path.lineTo(f, getHeight() / 2);
        path.close();
        Paint paint = this.c;
        canvas.drawPath(path, paint);
        path.reset();
        path.moveTo(getWidth() / 2, f2);
        path.arcTo(rectF, 270.0f, 90.0f, false);
        path.lineTo(f3, f2);
        path.lineTo(getWidth() / 2, f2);
        path.close();
        canvas.drawPath(path, paint);
        path.reset();
        path.moveTo(f3, getHeight() / 2);
        path.arcTo(rectF, DefinitionKt.NO_Float_VALUE, 90.0f, false);
        path.lineTo(f3, f4);
        path.lineTo(f3, getHeight() / 2);
        path.close();
        canvas.drawPath(path, paint);
        path.reset();
        path.moveTo(getWidth() / 2, f4);
        path.arcTo(rectF, 90.0f, 90.0f, false);
        path.lineTo(f, f4);
        path.lineTo(getWidth() / 2, f4);
        path.close();
        canvas.drawPath(path, paint);
        b(canvas);
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        d();
    }

    @Override // android.widget.ImageView
    public void setImageBitmap(Bitmap bitmap) {
        this.e = bitmap;
        d();
        invalidate();
    }

    @Override // android.widget.ImageView
    public void setImageDrawable(Drawable drawable) {
        Bitmap bitmap;
        if (drawable instanceof BitmapDrawable) {
            bitmap = ((BitmapDrawable) drawable).getBitmap();
        } else if (drawable != null) {
            int width = getWidth();
            int height = getHeight();
            ExecutorService executorService = n.a;
            Rect rect = new Rect();
            drawable.copyBounds(rect);
            if (rect.isEmpty()) {
                rect.set(0, 0, Math.max(width, drawable.getIntrinsicWidth()), Math.max(height, drawable.getIntrinsicHeight()));
                drawable.setBounds(rect);
            }
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(rect.width(), rect.height(), Bitmap.Config.ARGB_8888);
            drawable.draw(new Canvas(bitmapCreateBitmap));
            bitmap = bitmapCreateBitmap;
        } else {
            bitmap = null;
        }
        setImageBitmap(bitmap);
    }

    @Override // android.widget.ImageView
    @SuppressLint({"ResourceType"})
    public void setImageResource(int i) {
        setImageBitmap(i > 0 ? BitmapFactory.decodeResource(getResources(), i) : null);
    }

    @Override // android.widget.ImageView
    public void setImageURI(Uri uri) {
        if (this.g == null) {
            this.g = new b(this, 0);
        }
        this.g.o(uri);
    }

    public void setViewportOverlayColor(int i) {
        this.c.setColor(i);
        this.b.e = i;
    }

    public void setViewportOverlayPadding(int i) {
        this.b.d = i;
        d();
        invalidate();
    }

    public void setViewportRatio(float f) {
        float f2 = DefinitionKt.NO_Float_VALUE;
        if (Float.compare(f, DefinitionKt.NO_Float_VALUE) == 0) {
            f = getImageRatio();
        }
        k kVar = this.a;
        kVar.g = f;
        c cVar = kVar.a;
        if (f > DefinitionKt.NO_Float_VALUE) {
            f2 = f;
        }
        cVar.a = f2;
        d();
        invalidate();
    }

    public CropView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.c = new Paint();
        this.d = new Paint();
        this.f = new Matrix();
        this.h = 0;
        this.i = new Path();
        this.j = new RectF();
        c(context, attributeSet);
    }
}
