package androidx.camera.core.processing.concurrent;

import android.graphics.SurfaceTexture;
import android.opengl.EGL14;
import android.opengl.EGLDisplay;
import android.opengl.EGLExt;
import android.opengl.EGLSurface;
import android.opengl.GLES20;
import android.opengl.Matrix;
import android.util.Size;
import android.view.Surface;
import androidx.camera.core.C0196t;
import androidx.camera.core.Q;
import androidx.camera.core.processing.l;
import androidx.camera.core.processing.util.g;
import androidx.camera.core.processing.util.h;
import androidx.camera.core.processing.util.i;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class c extends androidx.camera.core.processing.e {
    public int n = -1;
    public int o = -1;
    public final Q p;
    public final Q q;

    public c(Q q, Q q2) {
        this.p = q;
        this.q = q2;
    }

    @Override // androidx.camera.core.processing.e
    public final androidx.camera.core.processing.util.a i(C0196t c0196t) {
        Map map = Collections.EMPTY_MAP;
        androidx.camera.core.processing.util.a aVarI = super.i(c0196t);
        this.n = i.h();
        this.o = i.h();
        return aVarI;
    }

    public final void x(long j, Surface surface, l lVar, SurfaceTexture surfaceTexture, SurfaceTexture surfaceTexture2) {
        i.d((AtomicBoolean) this.c, true);
        i.c((Thread) this.e);
        HashMap map = (HashMap) this.d;
        AbstractC3242q6.h("The surface is not registered.", map.containsKey(surface));
        androidx.camera.core.processing.util.c cVarD = (androidx.camera.core.processing.util.c) map.get(surface);
        Objects.requireNonNull(cVarD);
        if (cVarD == i.j) {
            cVarD = d(surface);
            if (cVarD == null) {
                return;
            } else {
                map.put(surface, cVarD);
            }
        }
        androidx.camera.core.processing.util.c cVar = cVarD;
        Surface surface2 = (Surface) this.j;
        EGLSurface eGLSurface = cVar.a;
        if (surface != surface2) {
            l(eGLSurface);
            this.j = surface;
        }
        GLES20.glClearColor(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 1.0f);
        GLES20.glClear(16384);
        y(cVar, lVar, surfaceTexture, this.p, this.n);
        y(cVar, lVar, surfaceTexture2, this.q, this.o);
        EGLExt.eglPresentationTimeANDROID((EGLDisplay) this.f, eGLSurface, j);
        if (EGL14.eglSwapBuffers((EGLDisplay) this.f, eGLSurface)) {
            return;
        }
        AbstractC3053s1.h("DualOpenGlRenderer", "Failed to swap buffers with EGL error: 0x" + Integer.toHexString(EGL14.eglGetError()));
        q(surface, false);
    }

    public final void y(androidx.camera.core.processing.util.c cVar, l lVar, SurfaceTexture surfaceTexture, Q q, int i) {
        s(i);
        int i2 = cVar.b;
        int i3 = cVar.c;
        GLES20.glViewport(0, 0, i2, i3);
        GLES20.glScissor(0, 0, i2, i3);
        float[] fArr = new float[16];
        surfaceTexture.getTransformMatrix(fArr);
        float[] fArr2 = new float[16];
        Matrix.multiplyMM(fArr2, 0, fArr, 0, lVar.e, 0);
        g gVar = (g) this.l;
        gVar.getClass();
        if (gVar instanceof h) {
            GLES20.glUniformMatrix4fv(((h) gVar).f, 1, false, fArr2, 0);
            i.b("glUniformMatrix4fv");
        }
        q.getClass();
        Size size = new Size((int) (i2 * 1.0f), (int) (i3 * 1.0f));
        Size size2 = new Size(i2, i3);
        float[] fArr3 = new float[16];
        Matrix.setIdentityM(fArr3, 0);
        float[] fArr4 = new float[16];
        Matrix.setIdentityM(fArr4, 0);
        float[] fArr5 = new float[16];
        Matrix.setIdentityM(fArr5, 0);
        Matrix.scaleM(fArr3, 0, size.getWidth() / size2.getWidth(), size.getHeight() / size2.getHeight(), 1.0f);
        Matrix.translateM(fArr4, 0, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
        Matrix.multiplyMM(fArr5, 0, fArr3, 0, fArr4, 0);
        GLES20.glUniformMatrix4fv(gVar.b, 1, false, fArr5, 0);
        i.b("glUniformMatrix4fv");
        GLES20.glUniform1f(gVar.c, 1.0f);
        i.b("glUniform1f");
        GLES20.glEnable(3042);
        GLES20.glBlendFuncSeparate(770, 771, 1, 771);
        GLES20.glDrawArrays(5, 0, 4);
        i.b("glDrawArrays");
        GLES20.glDisable(3042);
    }
}
