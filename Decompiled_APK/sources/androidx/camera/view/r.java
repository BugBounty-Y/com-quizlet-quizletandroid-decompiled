package androidx.camera.view;

import android.graphics.SurfaceTexture;
import android.view.TextureView;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.Objects;

/* loaded from: classes.dex */
public final class r implements TextureView.SurfaceTextureListener {
    public final /* synthetic */ s a;

    public r(s sVar) {
        this.a = sVar;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureAvailable(SurfaceTexture surfaceTexture, int i, int i2) {
        AbstractC3053s1.f(3, "TextureViewImpl");
        s sVar = this.a;
        sVar.f = surfaceTexture;
        if (sVar.g == null) {
            sVar.m();
            return;
        }
        sVar.h.getClass();
        Objects.toString(sVar.h);
        AbstractC3053s1.f(3, "TextureViewImpl");
        sVar.h.k.a();
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
        s sVar = this.a;
        sVar.f = null;
        androidx.concurrent.futures.l lVar = sVar.g;
        if (lVar == null) {
            AbstractC3053s1.f(3, "TextureViewImpl");
            return true;
        }
        com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(2, this, surfaceTexture);
        lVar.a(new androidx.camera.core.impl.utils.futures.h(0, lVar, bVar), androidx.core.content.c.d(sVar.e.getContext()));
        sVar.j = surfaceTexture;
        return false;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int i, int i2) {
        AbstractC3053s1.f(3, "TextureViewImpl");
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.a.k.getAndSet(null);
        if (iVar != null) {
            iVar.b(null);
        }
    }
}
