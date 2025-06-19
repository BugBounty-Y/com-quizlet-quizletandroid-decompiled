package androidx.camera.core.internal;

import android.graphics.SurfaceTexture;
import android.view.Surface;
import androidx.camera.core.W;
import androidx.camera.core.j0;
import com.google.android.gms.internal.mlkit_vision_barcode.T;

/* loaded from: classes.dex */
public final /* synthetic */ class d implements W {
    @Override // androidx.camera.core.W
    public final void a(j0 j0Var) {
        SurfaceTexture surfaceTexture = new SurfaceTexture(0);
        surfaceTexture.setDefaultBufferSize(j0Var.b.getWidth(), j0Var.b.getHeight());
        surfaceTexture.detachFromGLContext();
        Surface surface = new Surface(surfaceTexture);
        j0Var.a(surface, T.a(), new e(0, surface, surfaceTexture));
    }
}
