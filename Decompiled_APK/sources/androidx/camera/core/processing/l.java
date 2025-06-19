package androidx.camera.core.processing;

import android.graphics.RectF;
import android.opengl.Matrix;
import android.util.Size;
import android.view.Surface;
import androidx.activity.r;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.core.C0155g;
import androidx.camera.core.impl.InterfaceC0185y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.Closeable;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class l implements Closeable, AutoCloseable {
    public final Surface b;
    public final int c;
    public final Size d;
    public final float[] e;
    public androidx.core.util.a f;
    public androidx.camera.core.impl.utils.executor.e g;
    public final androidx.concurrent.futures.l j;
    public androidx.concurrent.futures.i k;
    public final Object a = new Object();
    public boolean h = false;
    public boolean i = false;

    public l(Surface surface, int i, Size size, C0155g c0155g, C0155g c0155g2) {
        float[] fArr = new float[16];
        this.e = fArr;
        this.b = surface;
        this.c = i;
        this.d = size;
        a(fArr, new float[16], c0155g);
        a(new float[16], new float[16], c0155g2);
        this.j = Y5.b(new C0132i(this, 8));
    }

    public static void a(float[] fArr, float[] fArr2, C0155g c0155g) {
        Matrix.setIdentityM(fArr, 0);
        if (c0155g == null) {
            return;
        }
        Q.c(fArr);
        int i = c0155g.d;
        Q.b(i, fArr);
        boolean z = c0155g.e;
        if (z) {
            Matrix.translateM(fArr, 0, 1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
            Matrix.scaleM(fArr, 0, -1.0f, 1.0f, 1.0f);
        }
        Size sizeE = androidx.camera.core.impl.utils.f.e(c0155g.a, i);
        float f = 0;
        android.graphics.Matrix matrixA = androidx.camera.core.impl.utils.f.a(new RectF(f, f, r6.getWidth(), r6.getHeight()), new RectF(f, f, sizeE.getWidth(), sizeE.getHeight()), i, z);
        RectF rectF = new RectF(c0155g.b);
        matrixA.mapRect(rectF);
        float width = rectF.left / sizeE.getWidth();
        float height = ((sizeE.getHeight() - rectF.height()) - rectF.top) / sizeE.getHeight();
        float fWidth = rectF.width() / sizeE.getWidth();
        float fHeight = rectF.height() / sizeE.getHeight();
        Matrix.translateM(fArr, 0, width, height, DefinitionKt.NO_Float_VALUE);
        Matrix.scaleM(fArr, 0, fWidth, fHeight, 1.0f);
        Matrix.setIdentityM(fArr2, 0);
        Q.c(fArr2);
        InterfaceC0185y interfaceC0185y = c0155g.c;
        if (interfaceC0185y != null) {
            AbstractC3242q6.h("Camera has no transform.", interfaceC0185y.l());
            Q.b(interfaceC0185y.n().a(), fArr2);
            if (interfaceC0185y.n().e() == 0) {
                Matrix.translateM(fArr2, 0, 1.0f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
                Matrix.scaleM(fArr2, 0, -1.0f, 1.0f, 1.0f);
            }
        }
        Matrix.invertM(fArr2, 0, fArr2, 0);
        Matrix.multiplyMM(fArr, 0, fArr2, 0, fArr, 0);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        synchronized (this.a) {
            try {
                if (!this.i) {
                    this.i = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        this.k.b(null);
    }

    public final Surface d(androidx.camera.core.impl.utils.executor.e eVar, androidx.core.util.a aVar) {
        boolean z;
        synchronized (this.a) {
            this.g = eVar;
            this.f = aVar;
            z = this.h;
        }
        if (z) {
            f();
        }
        return this.b;
    }

    public final void f() {
        androidx.camera.core.impl.utils.executor.e eVar;
        androidx.core.util.a aVar;
        AtomicReference atomicReference = new AtomicReference();
        synchronized (this.a) {
            try {
                if (this.g == null || (aVar = this.f) == null) {
                    this.h = true;
                } else if (!this.i) {
                    atomicReference.set(aVar);
                    eVar = this.g;
                    this.h = false;
                }
                eVar = null;
            } catch (Throwable th) {
                throw th;
            }
        }
        if (eVar != null) {
            try {
                eVar.execute(new r(18, this, atomicReference));
            } catch (RejectedExecutionException unused) {
                AbstractC3053s1.f(3, "SurfaceOutputImpl");
            }
        }
    }
}
