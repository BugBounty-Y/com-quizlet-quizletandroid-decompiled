package androidx.camera.view;

import android.graphics.Bitmap;
import android.graphics.SurfaceTexture;
import android.util.Size;
import android.view.Surface;
import android.view.TextureView;
import android.view.View;
import android.widget.FrameLayout;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.camera2.internal.C0143u;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.j0;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes.dex */
public final class s extends j {
    public TextureView e;
    public SurfaceTexture f;
    public androidx.concurrent.futures.l g;
    public j0 h;
    public boolean i;
    public SurfaceTexture j;
    public AtomicReference k;
    public T l;

    @Override // androidx.camera.view.j
    public final View c() {
        return this.e;
    }

    @Override // androidx.camera.view.j
    public final Bitmap d() {
        TextureView textureView = this.e;
        if (textureView == null || !textureView.isAvailable()) {
            return null;
        }
        return this.e.getBitmap();
    }

    @Override // androidx.camera.view.j
    public final void f() {
        if (!this.i || this.j == null) {
            return;
        }
        SurfaceTexture surfaceTexture = this.e.getSurfaceTexture();
        SurfaceTexture surfaceTexture2 = this.j;
        if (surfaceTexture != surfaceTexture2) {
            this.e.setSurfaceTexture(surfaceTexture2);
            this.j = null;
            this.i = false;
        }
    }

    @Override // androidx.camera.view.j
    public final void g() {
        this.i = true;
    }

    @Override // androidx.camera.view.j
    public final void h(j0 j0Var, T t) {
        Size size = j0Var.b;
        this.b = size;
        this.l = t;
        FrameLayout frameLayout = (FrameLayout) this.c;
        size.getClass();
        TextureView textureView = new TextureView(frameLayout.getContext());
        this.e = textureView;
        textureView.setLayoutParams(new FrameLayout.LayoutParams(((Size) this.b).getWidth(), ((Size) this.b).getHeight()));
        this.e.setSurfaceTextureListener(new r(this));
        frameLayout.removeAllViews();
        frameLayout.addView(this.e);
        j0 j0Var2 = this.h;
        if (j0Var2 != null) {
            j0Var2.c();
        }
        this.h = j0Var;
        Executor executorD = androidx.core.content.c.d(this.e.getContext());
        j0Var.j.a(new androidx.activity.r(22, this, j0Var), executorD);
        m();
    }

    @Override // androidx.camera.view.j
    public final com.google.common.util.concurrent.e l() {
        return Y5.b(new C0132i(this, 11));
    }

    public final void m() {
        SurfaceTexture surfaceTexture;
        Size size = (Size) this.b;
        if (size == null || (surfaceTexture = this.f) == null || this.h == null) {
            return;
        }
        surfaceTexture.setDefaultBufferSize(size.getWidth(), ((Size) this.b).getHeight());
        Surface surface = new Surface(this.f);
        j0 j0Var = this.h;
        androidx.concurrent.futures.l lVarB = Y5.b(new C0143u(11, this, surface));
        this.g = lVarB;
        lVarB.b.a(new androidx.camera.camera2.internal.compat.b(this, surface, lVarB, j0Var, 3), androidx.core.content.c.d(this.e.getContext()));
        this.a = true;
        i();
    }
}
