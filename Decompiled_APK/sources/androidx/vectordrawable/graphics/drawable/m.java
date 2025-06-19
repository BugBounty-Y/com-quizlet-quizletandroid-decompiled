package androidx.vectordrawable.graphics.drawable;

import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PathMeasure;
import android.graphics.PorterDuff;
import android.graphics.Shader;
import androidx.appcompat.widget.C0122z;
import androidx.collection.C0208f;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class m {
    public static final Matrix p = new Matrix();
    public final Path a;
    public final Path b;
    public final Matrix c;
    public Paint d;
    public Paint e;
    public PathMeasure f;
    public final j g;
    public float h;
    public float i;
    public float j;
    public float k;
    public int l;
    public String m;
    public Boolean n;
    public final C0208f o;

    public m() {
        this.c = new Matrix();
        this.h = DefinitionKt.NO_Float_VALUE;
        this.i = DefinitionKt.NO_Float_VALUE;
        this.j = DefinitionKt.NO_Float_VALUE;
        this.k = DefinitionKt.NO_Float_VALUE;
        this.l = 255;
        this.m = null;
        this.n = null;
        this.o = new C0208f(0);
        this.g = new j();
        this.a = new Path();
        this.b = new Path();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void a(j jVar, Matrix matrix, Canvas canvas, int i, int i2) {
        char c;
        float f;
        float f2;
        int i3;
        j jVar2 = jVar;
        char c2 = 1;
        jVar2.a.set(matrix);
        Matrix matrix2 = jVar2.a;
        matrix2.preConcat(jVar2.j);
        canvas.save();
        char c3 = 0;
        int i4 = 0;
        while (true) {
            ArrayList arrayList = jVar2.b;
            if (i4 >= arrayList.size()) {
                canvas.restore();
                return;
            }
            k kVar = (k) arrayList.get(i4);
            if (kVar instanceof j) {
                a((j) kVar, matrix2, canvas, i, i2);
            } else if (kVar instanceof l) {
                l lVar = (l) kVar;
                float f3 = i / this.j;
                float f4 = i2 / this.k;
                float fMin = Math.min(f3, f4);
                Matrix matrix3 = this.c;
                matrix3.set(matrix2);
                matrix3.postScale(f3, f4);
                float[] fArr = {DefinitionKt.NO_Float_VALUE, 1.0f, 1.0f, DefinitionKt.NO_Float_VALUE};
                matrix2.mapVectors(fArr);
                float fHypot = (float) Math.hypot(fArr[c3], fArr[c2]);
                boolean z = c2;
                boolean z2 = c3;
                float fHypot2 = (float) Math.hypot(fArr[2], fArr[3]);
                float f5 = (fArr[z2 ? 1 : 0] * fArr[3]) - (fArr[z ? 1 : 0] * fArr[2]);
                float fMax = Math.max(fHypot, fHypot2);
                float fAbs = fMax > DefinitionKt.NO_Float_VALUE ? Math.abs(f5) / fMax : 0.0f;
                if (fAbs != DefinitionKt.NO_Float_VALUE) {
                    Path path = this.a;
                    lVar.getClass();
                    path.reset();
                    androidx.core.graphics.g[] gVarArr = lVar.a;
                    if (gVarArr != null) {
                        androidx.core.graphics.g.b(gVarArr, path);
                    }
                    Path path2 = this.b;
                    path2.reset();
                    if (lVar instanceof h) {
                        path2.setFillType(lVar.c == 0 ? Path.FillType.WINDING : Path.FillType.EVEN_ODD);
                        path2.addPath(path, matrix3);
                        canvas.clipPath(path2);
                    } else {
                        i iVar = (i) lVar;
                        float f6 = iVar.i;
                        if (f6 != DefinitionKt.NO_Float_VALUE || iVar.j != 1.0f) {
                            float f7 = iVar.k;
                            float f8 = (f6 + f7) % 1.0f;
                            float f9 = (iVar.j + f7) % 1.0f;
                            if (this.f == null) {
                                this.f = new PathMeasure();
                            }
                            this.f.setPath(path, z2);
                            float length = this.f.getLength();
                            float f10 = f8 * length;
                            float f11 = f9 * length;
                            path.reset();
                            if (f10 > f11) {
                                this.f.getSegment(f10, length, path, z);
                                f = 0.0f;
                                this.f.getSegment(DefinitionKt.NO_Float_VALUE, f11, path, z);
                            } else {
                                f = 0.0f;
                                this.f.getSegment(f10, f11, path, z);
                            }
                            path.rLineTo(f, f);
                        }
                        path2.addPath(path, matrix3);
                        C0122z c0122z = iVar.f;
                        if ((((Shader) c0122z.c) == null && c0122z.b == 0) ? false : true) {
                            if (this.e == null) {
                                i3 = 16777215;
                                Paint paint = new Paint(1);
                                this.e = paint;
                                paint.setStyle(Paint.Style.FILL);
                            } else {
                                i3 = 16777215;
                            }
                            Paint paint2 = this.e;
                            Shader shader = (Shader) c0122z.c;
                            if (shader != null) {
                                shader.setLocalMatrix(matrix3);
                                paint2.setShader(shader);
                                paint2.setAlpha(Math.round(iVar.h * 255.0f));
                                f2 = 255.0f;
                            } else {
                                paint2.setShader(null);
                                paint2.setAlpha(255);
                                int i5 = c0122z.b;
                                float f12 = iVar.h;
                                PorterDuff.Mode mode = p.j;
                                f2 = 255.0f;
                                paint2.setColor((i5 & i3) | (((int) (Color.alpha(i5) * f12)) << 24));
                            }
                            paint2.setColorFilter(null);
                            path2.setFillType(iVar.c == 0 ? Path.FillType.WINDING : Path.FillType.EVEN_ODD);
                            canvas.drawPath(path2, paint2);
                        } else {
                            f2 = 255.0f;
                            i3 = 16777215;
                        }
                        C0122z c0122z2 = iVar.d;
                        if (((Shader) c0122z2.c) != null || c0122z2.b != 0) {
                            if (this.d == null) {
                                Paint paint3 = new Paint(1);
                                this.d = paint3;
                                paint3.setStyle(Paint.Style.STROKE);
                            }
                            Paint paint4 = this.d;
                            Paint.Join join = iVar.m;
                            if (join != null) {
                                paint4.setStrokeJoin(join);
                            }
                            Paint.Cap cap = iVar.l;
                            if (cap != null) {
                                paint4.setStrokeCap(cap);
                            }
                            paint4.setStrokeMiter(iVar.n);
                            Shader shader2 = (Shader) c0122z2.c;
                            if (shader2 != null) {
                                shader2.setLocalMatrix(matrix3);
                                paint4.setShader(shader2);
                                paint4.setAlpha(Math.round(iVar.g * f2));
                            } else {
                                paint4.setShader(null);
                                paint4.setAlpha(255);
                                int i6 = c0122z2.b;
                                float f13 = iVar.g;
                                PorterDuff.Mode mode2 = p.j;
                                paint4.setColor((i6 & i3) | (((int) (Color.alpha(i6) * f13)) << 24));
                            }
                            paint4.setColorFilter(null);
                            paint4.setStrokeWidth(iVar.e * fMin * fAbs);
                            canvas.drawPath(path2, paint4);
                        }
                    }
                }
                c = 1;
                i4++;
                jVar2 = jVar;
                c2 = c;
                c3 = 0;
            }
            c = c2;
            i4++;
            jVar2 = jVar;
            c2 = c;
            c3 = 0;
        }
    }

    public float getAlpha() {
        return getRootAlpha() / 255.0f;
    }

    public int getRootAlpha() {
        return this.l;
    }

    public void setAlpha(float f) {
        setRootAlpha((int) (f * 255.0f));
    }

    public void setRootAlpha(int i) {
        this.l = i;
    }

    public m(m mVar) {
        this.c = new Matrix();
        this.h = DefinitionKt.NO_Float_VALUE;
        this.i = DefinitionKt.NO_Float_VALUE;
        this.j = DefinitionKt.NO_Float_VALUE;
        this.k = DefinitionKt.NO_Float_VALUE;
        this.l = 255;
        this.m = null;
        this.n = null;
        C0208f c0208f = new C0208f(0);
        this.o = c0208f;
        this.g = new j(mVar.g, c0208f);
        this.a = new Path(mVar.a);
        this.b = new Path(mVar.b);
        this.h = mVar.h;
        this.i = mVar.i;
        this.j = mVar.j;
        this.k = mVar.k;
        this.l = mVar.l;
        this.m = mVar.m;
        String str = mVar.m;
        if (str != null) {
            c0208f.put(str, this);
        }
        this.n = mVar.n;
    }
}
