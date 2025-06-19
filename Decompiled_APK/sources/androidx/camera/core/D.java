package androidx.camera.core;

import android.graphics.Matrix;
import android.graphics.Rect;
import android.graphics.RectF;
import android.media.ImageWriter;
import androidx.camera.camera2.internal.C0132i;
import androidx.core.os.OperationCanceledException;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.nio.ByteBuffer;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public abstract class D implements androidx.camera.core.impl.Q {
    public C0132i a;
    public volatile int b;
    public volatile int c;
    public volatile boolean e;
    public volatile boolean f;
    public Executor g;
    public a0 h;
    public ImageWriter i;
    public ByteBuffer n;
    public ByteBuffer o;
    public ByteBuffer p;
    public ByteBuffer q;
    public volatile int d = 1;
    public Rect j = new Rect();
    public Rect k = new Rect();
    public Matrix l = new Matrix();
    public Matrix m = new Matrix();
    public final Object r = new Object();
    public boolean s = true;

    public abstract O a(androidx.camera.core.impl.S s);

    public final com.google.common.util.concurrent.e b(final O o) throws Throwable {
        Object obj;
        final Executor executor;
        final C0132i c0132i;
        boolean z;
        a0 a0Var;
        ImageWriter imageWriter;
        ByteBuffer byteBuffer;
        ByteBuffer byteBuffer2;
        ByteBuffer byteBuffer3;
        ByteBuffer byteBuffer4;
        G g;
        G gE;
        int i = this.e ? this.b : 0;
        Object obj2 = this.r;
        synchronized (obj2) {
            try {
                try {
                    executor = this.g;
                    c0132i = this.a;
                    z = this.e && i != this.c;
                    if (z) {
                        h(o, i);
                    }
                    if (this.e) {
                        d(o);
                    }
                    try {
                        a0Var = this.h;
                        try {
                            imageWriter = this.i;
                            byteBuffer = this.n;
                            try {
                                byteBuffer2 = this.o;
                                byteBuffer3 = this.p;
                                byteBuffer4 = this.q;
                            } catch (Throwable th) {
                                th = th;
                                obj = obj2;
                                throw th;
                            }
                        } catch (Throwable th2) {
                            th = th2;
                            obj = obj2;
                        }
                    } catch (Throwable th3) {
                        th = th3;
                        obj = obj2;
                    }
                } catch (Throwable th4) {
                    th = th4;
                    obj = obj2;
                }
            } catch (Throwable th5) {
                th = th5;
            }
        }
        if (c0132i == null || executor == null || !this.s) {
            return new androidx.camera.core.impl.utils.futures.k(new OperationCanceledException("No analyzer or executor currently set."), 1);
        }
        if (a0Var == null) {
            g = null;
        } else {
            if (this.d == 2) {
                gE = ImageProcessingUtil.b(o, a0Var, byteBuffer, i, this.f);
            } else {
                if (this.d == 1) {
                    if (this.f) {
                        ImageProcessingUtil.a(o);
                    }
                    if (imageWriter != null && byteBuffer2 != null && byteBuffer3 != null && byteBuffer4 != null) {
                        gE = ImageProcessingUtil.e(o, a0Var, imageWriter, byteBuffer2, byteBuffer3, byteBuffer4, i);
                    }
                }
                g = null;
            }
            g = gE;
        }
        boolean z2 = g == null;
        final O o2 = z2 ? o : g;
        final Rect rect = new Rect();
        final Matrix matrix = new Matrix();
        synchronized (this.r) {
            if (z && !z2) {
                try {
                    g(o.getWidth(), o.b(), o2.getWidth(), o2.b());
                } finally {
                }
            }
            this.c = i;
            rect.set(this.k);
            matrix.set(this.m);
        }
        return Y5.b(new androidx.concurrent.futures.j() { // from class: androidx.camera.core.C
            @Override // androidx.concurrent.futures.j
            public final Object d(final androidx.concurrent.futures.i iVar) {
                final D d = this.a;
                final O o3 = o;
                final Matrix matrix2 = matrix;
                final Rect rect2 = rect;
                final C0132i c0132i2 = c0132i;
                final O o4 = o2;
                executor.execute(new Runnable() { // from class: androidx.camera.core.B
                    /* JADX WARN: Removed duplicated region for block: B:139:0x0280 A[EXC_TOP_SPLITTER, SYNTHETIC] */
                    /* JADX WARN: Removed duplicated region for block: B:72:0x01c2  */
                    /* JADX WARN: Removed duplicated region for block: B:73:0x01c7  */
                    /* JADX WARN: Removed duplicated region for block: B:78:0x01f4  */
                    /* JADX WARN: Removed duplicated region for block: B:91:0x0214  */
                    /* JADX WARN: Removed duplicated region for block: B:94:0x0266  */
                    /* JADX WARN: Removed duplicated region for block: B:95:0x026d  */
                    @Override // java.lang.Runnable
                    /*
                        Code decompiled incorrectly, please refer to instructions dump.
                        To view partially-correct add '--show-bad-code' argument
                    */
                    public final void run() {
                        /*
                            Method dump skipped, instructions count: 807
                            To view this dump add '--comments-level debug' option
                        */
                        throw new UnsupportedOperationException("Method not decompiled: androidx.camera.core.B.run():void");
                    }
                });
                return "analyzeImage";
            }
        });
    }

    public abstract void c();

    public final void d(O o) {
        if (this.d != 1) {
            if (this.d == 2 && this.n == null) {
                this.n = ByteBuffer.allocateDirect(o.b() * o.getWidth() * 4);
                return;
            }
            return;
        }
        if (this.o == null) {
            this.o = ByteBuffer.allocateDirect(o.b() * o.getWidth());
        }
        this.o.position(0);
        if (this.p == null) {
            this.p = ByteBuffer.allocateDirect((o.b() * o.getWidth()) / 4);
        }
        this.p.position(0);
        if (this.q == null) {
            this.q = ByteBuffer.allocateDirect((o.b() * o.getWidth()) / 4);
        }
        this.q.position(0);
    }

    @Override // androidx.camera.core.impl.Q
    public final void e(androidx.camera.core.impl.S s) {
        try {
            O oA = a(s);
            if (oA != null) {
                f(oA);
            }
        } catch (IllegalStateException e) {
            AbstractC3053s1.d("ImageAnalysisAnalyzer", "Failed to acquire image.", e);
        }
    }

    public abstract void f(O o);

    public final void g(int i, int i2, int i3, int i4) {
        int i5 = this.b;
        Matrix matrix = new Matrix();
        if (i5 > 0) {
            RectF rectF = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, i, i2);
            RectF rectF2 = androidx.camera.core.impl.utils.f.a;
            Matrix.ScaleToFit scaleToFit = Matrix.ScaleToFit.FILL;
            matrix.setRectToRect(rectF, rectF2, scaleToFit);
            matrix.postRotate(i5);
            RectF rectF3 = new RectF(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, i3, i4);
            Matrix matrix2 = new Matrix();
            matrix2.setRectToRect(rectF2, rectF3, scaleToFit);
            matrix.postConcat(matrix2);
        }
        RectF rectF4 = new RectF(this.j);
        matrix.mapRect(rectF4);
        Rect rect = new Rect();
        rectF4.round(rect);
        this.k = rect;
        this.m.setConcat(this.l, matrix);
    }

    public final void h(O o, int i) {
        a0 a0Var = this.h;
        if (a0Var == null) {
            return;
        }
        a0Var.g();
        int width = o.getWidth();
        int iB = o.b();
        int iM = this.h.m();
        int iC = this.h.C();
        boolean z = i == 90 || i == 270;
        int i2 = z ? iB : width;
        if (!z) {
            width = iB;
        }
        this.h = new a0(com.google.android.gms.dynamite.d.c(i2, width, iM, iC));
        if (this.d == 1) {
            ImageWriter imageWriter = this.i;
            if (imageWriter != null) {
                imageWriter.close();
            }
            this.i = ImageWriter.newInstance(this.h.w(), this.h.C());
        }
    }
}
