package androidx.constraintlayout.motion.widget;

import android.graphics.Canvas;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.Rect;
import android.view.View;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Serializable;

/* loaded from: classes.dex */
public class n {
    public final /* synthetic */ int a;
    public int b;
    public int c;
    public Object d;
    public Serializable e;
    public Serializable f;
    public Serializable g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;

    public n() {
        this.a = 1;
        this.d = new com.google.android.gms.cloudmessaging.k(9);
        this.k = "";
    }

    public String a() {
        return (String) this.j;
    }

    public String b() {
        return (String) this.f;
    }

    public int c() {
        return this.b;
    }

    public void d(Canvas canvas, int i, int i2, j jVar) {
        Canvas canvas2;
        int width;
        int height;
        boolean z;
        float f;
        int[] iArr = (int[]) this.g;
        boolean z2 = false;
        int i3 = 4;
        if (i == 4) {
            int i4 = 0;
            boolean z3 = false;
            boolean z4 = false;
            while (i4 < this.b) {
                int i5 = iArr[i4];
                boolean z5 = z3;
                if (i5 == 1) {
                    z5 = true;
                }
                if (i5 == 0) {
                    z4 = true;
                }
                i4++;
                z3 = z5;
                z4 = z4;
            }
            if (z3) {
                float[] fArr = (float[]) this.d;
                canvas.drawLine(fArr[0], fArr[1], fArr[fArr.length - 2], fArr[fArr.length - 1], (Paint) this.k);
            }
            if (z4) {
                e(canvas);
            }
        }
        if (i == 2) {
            float[] fArr2 = (float[]) this.d;
            canvas2 = canvas;
            canvas2.drawLine(fArr2[0], fArr2[1], fArr2[fArr2.length - 2], fArr2[fArr2.length - 1], (Paint) this.k);
        } else {
            canvas2 = canvas;
        }
        if (i == 3) {
            e(canvas);
        }
        canvas2.drawLines((float[]) this.d, (Paint) this.i);
        View view = jVar.b;
        if (view != null) {
            width = view.getWidth();
            height = jVar.b.getHeight();
        } else {
            width = 0;
            height = 0;
        }
        int i6 = 1;
        while (i6 < i2 - 1) {
            if (i == i3 && iArr[i6 - 1] == 0) {
                z = z2;
            } else {
                int i7 = i6 * 2;
                float[] fArr3 = (float[]) this.e;
                float f2 = fArr3[i7];
                float f3 = fArr3[i7 + 1];
                ((Path) this.h).reset();
                z = z2;
                ((Path) this.h).moveTo(f2, f3 + 10.0f);
                ((Path) this.h).lineTo(f2 + 10.0f, f3);
                ((Path) this.h).lineTo(f2, f3 - 10.0f);
                ((Path) this.h).lineTo(f2 - 10.0f, f3);
                ((Path) this.h).close();
                int i8 = i6 - 1;
                Paint paint = (Paint) this.m;
                if (i == i3) {
                    int i9 = iArr[i8];
                    if (i9 == 1) {
                        g(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f3 - DefinitionKt.NO_Float_VALUE);
                    } else if (i9 == 0) {
                        f(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f3 - DefinitionKt.NO_Float_VALUE);
                    } else {
                        if (i9 == 2) {
                            f = f3;
                            h(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f - DefinitionKt.NO_Float_VALUE, width, height);
                        }
                        canvas2.drawPath((Path) this.h, paint);
                    }
                    f = f3;
                    canvas2.drawPath((Path) this.h, paint);
                } else {
                    f = f3;
                }
                if (i == 2) {
                    g(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f - DefinitionKt.NO_Float_VALUE);
                }
                if (i == 3) {
                    f(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f - DefinitionKt.NO_Float_VALUE);
                }
                if (i == 6) {
                    h(canvas2, f2 - DefinitionKt.NO_Float_VALUE, f - DefinitionKt.NO_Float_VALUE, width, height);
                }
                canvas2.drawPath((Path) this.h, paint);
            }
            i6++;
            z2 = z;
            i3 = 4;
        }
        boolean z6 = z2;
        float[] fArr4 = (float[]) this.d;
        if (fArr4.length > 1) {
            float f4 = fArr4[z6 ? 1 : 0];
            float f5 = fArr4[1];
            Paint paint2 = (Paint) this.j;
            canvas2.drawCircle(f4, f5, 8.0f, paint2);
            float[] fArr5 = (float[]) this.d;
            canvas2.drawCircle(fArr5[fArr5.length - 2], fArr5[fArr5.length - 1], 8.0f, paint2);
        }
    }

    public void e(Canvas canvas) {
        float[] fArr = (float[]) this.d;
        float f = fArr[0];
        float f2 = fArr[1];
        float f3 = fArr[fArr.length - 2];
        float f4 = fArr[fArr.length - 1];
        float fMin = Math.min(f, f3);
        float fMax = Math.max(f2, f4);
        float fMax2 = Math.max(f, f3);
        float fMax3 = Math.max(f2, f4);
        Paint paint = (Paint) this.k;
        canvas.drawLine(fMin, fMax, fMax2, fMax3, paint);
        canvas.drawLine(Math.min(f, f3), Math.min(f2, f4), Math.min(f, f3), Math.max(f2, f4), paint);
    }

    public void f(Canvas canvas, float f, float f2) {
        float[] fArr = (float[]) this.d;
        float f3 = fArr[0];
        float f4 = fArr[1];
        float f5 = fArr[fArr.length - 2];
        float f6 = fArr[fArr.length - 1];
        float fMin = Math.min(f3, f5);
        float fMax = Math.max(f4, f6);
        float fMin2 = f - Math.min(f3, f5);
        float fMax2 = Math.max(f4, f6) - f2;
        String str = "" + (((int) (((fMin2 * 100.0f) / Math.abs(f5 - f3)) + 0.5d)) / 100.0f);
        Paint paint = (Paint) this.l;
        paint.getTextBounds(str, 0, str.length(), (Rect) this.n);
        Rect rect = (Rect) this.n;
        canvas.drawText(str, ((fMin2 / 2.0f) - (rect.width() / 2)) + fMin, f2 - 20.0f, paint);
        float fMin3 = Math.min(f3, f5);
        Paint paint2 = (Paint) this.k;
        canvas.drawLine(f, f2, fMin3, f2, paint2);
        String str2 = "" + (((int) (((fMax2 * 100.0f) / Math.abs(f6 - f4)) + 0.5d)) / 100.0f);
        paint.getTextBounds(str2, 0, str2.length(), (Rect) this.n);
        canvas.drawText(str2, f + 5.0f, fMax - ((fMax2 / 2.0f) - (rect.height() / 2)), paint);
        canvas.drawLine(f, f2, f, Math.max(f4, f6), paint2);
    }

    public void g(Canvas canvas, float f, float f2) {
        float[] fArr = (float[]) this.d;
        float f3 = fArr[0];
        float f4 = fArr[1];
        float f5 = fArr[fArr.length - 2];
        float f6 = fArr[fArr.length - 1];
        float fHypot = (float) Math.hypot(f3 - f5, f4 - f6);
        float f7 = f5 - f3;
        float f8 = f6 - f4;
        float f9 = (((f2 - f4) * f8) + ((f - f3) * f7)) / (fHypot * fHypot);
        float f10 = (f7 * f9) + f3;
        float f11 = (f9 * f8) + f4;
        Path path = new Path();
        path.moveTo(f, f2);
        path.lineTo(f10, f11);
        float fHypot2 = (float) Math.hypot(f10 - f, f11 - f2);
        String str = "" + (((int) ((fHypot2 * 100.0f) / fHypot)) / 100.0f);
        Paint paint = (Paint) this.l;
        paint.getTextBounds(str, 0, str.length(), (Rect) this.n);
        canvas.drawTextOnPath(str, path, (fHypot2 / 2.0f) - (((Rect) this.n).width() / 2), -20.0f, paint);
        canvas.drawLine(f, f2, f10, f11, (Paint) this.k);
    }

    public void h(Canvas canvas, float f, float f2, int i, int i2) {
        StringBuilder sb = new StringBuilder("");
        r rVar = (r) this.o;
        sb.append(((int) ((((f - (i / 2)) * 100.0f) / (rVar.getWidth() - i)) + 0.5d)) / 100.0f);
        String string = sb.toString();
        Paint paint = (Paint) this.l;
        paint.getTextBounds(string, 0, string.length(), (Rect) this.n);
        Rect rect = (Rect) this.n;
        canvas.drawText(string, ((f / 2.0f) - (rect.width() / 2)) + DefinitionKt.NO_Float_VALUE, f2 - 20.0f, paint);
        float fMin = Math.min(DefinitionKt.NO_Float_VALUE, 1.0f);
        Paint paint2 = (Paint) this.k;
        canvas.drawLine(f, f2, fMin, f2, paint2);
        String str = "" + (((int) ((((f2 - (i2 / 2)) * 100.0f) / (rVar.getHeight() - i2)) + 0.5d)) / 100.0f);
        paint.getTextBounds(str, 0, str.length(), (Rect) this.n);
        canvas.drawText(str, f + 5.0f, DefinitionKt.NO_Float_VALUE - ((f2 / 2.0f) - (rect.height() / 2)), paint);
        canvas.drawLine(f, f2, f, Math.max(DefinitionKt.NO_Float_VALUE, 1.0f), paint2);
    }

    public String toString() {
        switch (this.a) {
            case 1:
                StringBuilder sb = new StringBuilder("ButtonProperty{fontProperty=");
                sb.append((com.google.android.gms.cloudmessaging.k) this.d);
                sb.append(", backGroundColor='");
                sb.append((String) this.e);
                sb.append("', textColor='");
                sb.append((String) this.f);
                sb.append("', borderColor='");
                sb.append((String) this.g);
                sb.append("', borderWidth='");
                sb.append((String) this.h);
                sb.append("', borderRadius='");
                sb.append((String) this.i);
                sb.append("', text='");
                sb.append((String) this.j);
                sb.append("', position='");
                sb.append(this.c);
                sb.append("', show='");
                return android.support.v4.media.session.a.t(sb, (String) this.k, "'}");
            default:
                return super.toString();
        }
    }

    /* JADX WARN: Type inference failed for: r6v11, types: [float[], java.io.Serializable] */
    /* JADX WARN: Type inference failed for: r6v13, types: [int[], java.io.Serializable] */
    /* JADX WARN: Type inference failed for: r6v7, types: [float[], java.io.Serializable] */
    public n(r rVar) {
        this.a = 0;
        this.o = rVar;
        this.n = new Rect();
        this.c = 1;
        Paint paint = new Paint();
        this.i = paint;
        paint.setAntiAlias(true);
        paint.setColor(-21965);
        paint.setStrokeWidth(2.0f);
        Paint.Style style = Paint.Style.STROKE;
        paint.setStyle(style);
        Paint paint2 = new Paint();
        this.j = paint2;
        paint2.setAntiAlias(true);
        paint2.setColor(-2067046);
        paint2.setStrokeWidth(2.0f);
        paint2.setStyle(style);
        Paint paint3 = new Paint();
        this.k = paint3;
        paint3.setAntiAlias(true);
        paint3.setColor(-13391360);
        paint3.setStrokeWidth(2.0f);
        paint3.setStyle(style);
        Paint paint4 = new Paint();
        this.l = paint4;
        paint4.setAntiAlias(true);
        paint4.setColor(-13391360);
        paint4.setTextSize(rVar.getContext().getResources().getDisplayMetrics().density * 12.0f);
        this.f = new float[8];
        Paint paint5 = new Paint();
        this.m = paint5;
        paint5.setAntiAlias(true);
        paint3.setPathEffect(new DashPathEffect(new float[]{4.0f, 8.0f}, DefinitionKt.NO_Float_VALUE));
        this.e = new float[100];
        this.g = new int[50];
    }
}
