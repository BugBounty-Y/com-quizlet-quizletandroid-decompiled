package androidx.camera.core.processing;

import android.graphics.Bitmap;
import android.graphics.SurfaceTexture;
import android.opengl.GLES20;
import android.opengl.Matrix;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Surface;
import androidx.activity.RunnableC0041m;
import androidx.activity.r;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.RunnableC0131h;
import androidx.camera.core.C0196t;
import androidx.camera.core.ImageProcessingUtil;
import androidx.camera.core.e0;
import androidx.camera.core.j0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.v;

/* loaded from: classes.dex */
public final class c implements m, SurfaceTexture.OnFrameAvailableListener {
    public final e a;
    public final HandlerThread b;
    public final androidx.camera.core.impl.utils.executor.e c;
    public final Handler d;
    public final AtomicBoolean e;
    public final float[] f;
    public final float[] g;
    public final LinkedHashMap h;
    public int i;
    public boolean j;
    public final ArrayList k;

    public c(C0196t c0196t) {
        Map map = Collections.EMPTY_MAP;
        this.e = new AtomicBoolean(false);
        this.f = new float[16];
        this.g = new float[16];
        this.h = new LinkedHashMap();
        this.i = 0;
        this.j = false;
        this.k = new ArrayList();
        HandlerThread handlerThread = new HandlerThread("GL Thread");
        this.b = handlerThread;
        handlerThread.start();
        Handler handler = new Handler(handlerThread.getLooper());
        this.d = handler;
        this.c = new androidx.camera.core.impl.utils.executor.e(handler);
        this.a = new e();
        try {
            try {
                Y5.b(new C0143u(this, c0196t)).get();
            } catch (InterruptedException | ExecutionException e) {
                e = e;
                e = e instanceof ExecutionException ? e.getCause() : e;
                if (!(e instanceof RuntimeException)) {
                    throw new IllegalStateException("Failed to create DefaultSurfaceProcessor", e);
                }
                throw ((RuntimeException) e);
            }
        } catch (RuntimeException e2) {
            a();
            throw e2;
        }
    }

    @Override // androidx.camera.core.processing.m
    public final void a() {
        if (this.e.getAndSet(true)) {
            return;
        }
        e(new RunnableC0041m(this, 19), new RunnableC0131h(0));
    }

    @Override // androidx.camera.core.processing.m
    public final void b(l lVar) {
        if (this.e.get()) {
            lVar.close();
            return;
        }
        r rVar = new r(16, this, lVar);
        Objects.requireNonNull(lVar);
        e(rVar, new RunnableC0041m(lVar, 18));
    }

    @Override // androidx.camera.core.processing.m
    public final void c(j0 j0Var) {
        if (this.e.get()) {
            j0Var.c();
        } else {
            e(new r(17, this, j0Var), new e0(j0Var, 1));
        }
    }

    public final void d() {
        if (this.j && this.i == 0) {
            LinkedHashMap linkedHashMap = this.h;
            Iterator it2 = linkedHashMap.keySet().iterator();
            while (it2.hasNext()) {
                ((l) it2.next()).close();
            }
            Iterator it3 = this.k.iterator();
            if (it3.hasNext()) {
                ((a) it3.next()).getClass();
                new Exception("Failed to snapshot: DefaultSurfaceProcessor is released.");
                throw null;
            }
            linkedHashMap.clear();
            e eVar = this.a;
            if (((AtomicBoolean) eVar.c).getAndSet(false)) {
                androidx.camera.core.processing.util.i.c((Thread) eVar.e);
                eVar.p();
            }
            this.b.quit();
        }
    }

    public final void e(Runnable runnable, Runnable runnable2) {
        try {
            this.c.execute(new RunnableC0130g(this, runnable2, runnable, 4));
        } catch (RejectedExecutionException e) {
            AbstractC3053s1.i("DefaultSurfaceProcessor", "Unable to executor runnable", e);
            runnable2.run();
        }
    }

    public final void f(Exception exc) {
        ArrayList arrayList = this.k;
        Iterator it2 = arrayList.iterator();
        if (it2.hasNext()) {
            ((a) it2.next()).getClass();
            throw null;
        }
        arrayList.clear();
    }

    public final Bitmap g(Size size, float[] fArr, int i) {
        float[] fArr2 = (float[]) fArr.clone();
        Q.b(i, fArr2);
        Q.c(fArr2);
        Size sizeE = androidx.camera.core.impl.utils.f.e(size, i);
        e eVar = this.a;
        eVar.getClass();
        ByteBuffer byteBufferAllocateDirect = ByteBuffer.allocateDirect(sizeE.getHeight() * sizeE.getWidth() * 4);
        AbstractC3242q6.c("ByteBuffer capacity is not equal to width * height * 4.", byteBufferAllocateDirect.capacity() == (sizeE.getHeight() * sizeE.getWidth()) * 4);
        AbstractC3242q6.c("ByteBuffer is not direct.", byteBufferAllocateDirect.isDirect());
        int[] iArr = androidx.camera.core.processing.util.i.a;
        int[] iArr2 = new int[1];
        GLES20.glGenTextures(1, iArr2, 0);
        androidx.camera.core.processing.util.i.b("glGenTextures");
        int i2 = iArr2[0];
        GLES20.glActiveTexture(33985);
        androidx.camera.core.processing.util.i.b("glActiveTexture");
        GLES20.glBindTexture(3553, i2);
        androidx.camera.core.processing.util.i.b("glBindTexture");
        GLES20.glTexImage2D(3553, 0, 6407, sizeE.getWidth(), sizeE.getHeight(), 0, 6407, 5121, null);
        androidx.camera.core.processing.util.i.b("glTexImage2D");
        GLES20.glTexParameteri(3553, 10240, 9729);
        GLES20.glTexParameteri(3553, 10241, 9729);
        int[] iArr3 = new int[1];
        GLES20.glGenFramebuffers(1, iArr3, 0);
        androidx.camera.core.processing.util.i.b("glGenFramebuffers");
        int i3 = iArr3[0];
        GLES20.glBindFramebuffer(36160, i3);
        androidx.camera.core.processing.util.i.b("glBindFramebuffer");
        GLES20.glFramebufferTexture2D(36160, 36064, 3553, i2, 0);
        androidx.camera.core.processing.util.i.b("glFramebufferTexture2D");
        GLES20.glActiveTexture(33984);
        androidx.camera.core.processing.util.i.b("glActiveTexture");
        GLES20.glBindTexture(36197, eVar.a);
        androidx.camera.core.processing.util.i.b("glBindTexture");
        eVar.j = null;
        GLES20.glViewport(0, 0, sizeE.getWidth(), sizeE.getHeight());
        GLES20.glScissor(0, 0, sizeE.getWidth(), sizeE.getHeight());
        androidx.camera.core.processing.util.g gVar = (androidx.camera.core.processing.util.g) eVar.l;
        gVar.getClass();
        if (gVar instanceof androidx.camera.core.processing.util.h) {
            GLES20.glUniformMatrix4fv(((androidx.camera.core.processing.util.h) gVar).f, 1, false, fArr2, 0);
            androidx.camera.core.processing.util.i.b("glUniformMatrix4fv");
        }
        GLES20.glDrawArrays(5, 0, 4);
        androidx.camera.core.processing.util.i.b("glDrawArrays");
        GLES20.glReadPixels(0, 0, sizeE.getWidth(), sizeE.getHeight(), 6408, 5121, byteBufferAllocateDirect);
        androidx.camera.core.processing.util.i.b("glReadPixels");
        GLES20.glBindFramebuffer(36160, 0);
        GLES20.glDeleteTextures(1, new int[]{i2}, 0);
        androidx.camera.core.processing.util.i.b("glDeleteTextures");
        GLES20.glDeleteFramebuffers(1, new int[]{i3}, 0);
        androidx.camera.core.processing.util.i.b("glDeleteFramebuffers");
        int i4 = eVar.a;
        GLES20.glActiveTexture(33984);
        androidx.camera.core.processing.util.i.b("glActiveTexture");
        GLES20.glBindTexture(36197, i4);
        androidx.camera.core.processing.util.i.b("glBindTexture");
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(sizeE.getWidth(), sizeE.getHeight(), Bitmap.Config.ARGB_8888);
        byteBufferAllocateDirect.rewind();
        ImageProcessingUtil.c(bitmapCreateBitmap, byteBufferAllocateDirect, sizeE.getWidth() * 4);
        return bitmapCreateBitmap;
    }

    public final void h(v vVar) throws IOException {
        ArrayList arrayList = this.k;
        if (arrayList.isEmpty()) {
            return;
        }
        if (vVar == null) {
            f(new Exception("Failed to snapshot: no JPEG Surface."));
            return;
        }
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            try {
                Iterator it2 = arrayList.iterator();
                if (!it2.hasNext()) {
                    byteArrayOutputStream.close();
                    return;
                }
                ((a) it2.next()).getClass();
                Bitmap bitmapG = g((Size) vVar.b, (float[]) vVar.c, 0);
                byteArrayOutputStream.reset();
                bitmapG.compress(Bitmap.CompressFormat.JPEG, 0, byteArrayOutputStream);
                byte[] byteArray = byteArrayOutputStream.toByteArray();
                Surface surface = (Surface) vVar.a;
                Objects.requireNonNull(byteArray);
                ImageProcessingUtil.f(byteArray, surface);
                throw null;
            } finally {
            }
        } catch (IOException e) {
            f(e);
        }
    }

    @Override // android.graphics.SurfaceTexture.OnFrameAvailableListener
    public final void onFrameAvailable(SurfaceTexture surfaceTexture) throws IOException {
        if (this.e.get()) {
            return;
        }
        surfaceTexture.updateTexImage();
        float[] fArr = this.f;
        surfaceTexture.getTransformMatrix(fArr);
        v vVar = null;
        for (Map.Entry entry : this.h.entrySet()) {
            Surface surface = (Surface) entry.getValue();
            l lVar = (l) entry.getKey();
            float[] fArr2 = lVar.e;
            float[] fArr3 = this.g;
            Matrix.multiplyMM(fArr3, 0, fArr, 0, fArr2, 0);
            int i = lVar.c;
            if (i == 34) {
                try {
                    this.a.r(surfaceTexture.getTimestamp(), fArr3, surface);
                } catch (RuntimeException e) {
                    AbstractC3053s1.d("DefaultSurfaceProcessor", "Failed to render with OpenGL.", e);
                }
            } else {
                AbstractC3242q6.h("Unsupported format: " + i, i == 256);
                AbstractC3242q6.h("Only one JPEG output is supported.", vVar == null);
                vVar = new v(surface, lVar.d, (float[]) fArr3.clone());
            }
        }
        try {
            h(vVar);
        } catch (RuntimeException e2) {
            f(e2);
        }
    }
}
