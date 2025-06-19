package androidx.camera.view;

import android.graphics.Bitmap;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.PixelCopy;
import android.view.SurfaceView;
import android.view.View;
import android.widget.FrameLayout;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.RunnableC0130g;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.j0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class q extends j {
    public SurfaceView e;
    public final p f;

    public q(FrameLayout frameLayout, c cVar) {
        super(frameLayout, cVar);
        this.f = new p(this);
    }

    @Override // androidx.camera.view.j
    public final View c() {
        return this.e;
    }

    @Override // androidx.camera.view.j
    public final Bitmap d() {
        SurfaceView surfaceView = this.e;
        if (surfaceView == null || surfaceView.getHolder().getSurface() == null || !this.e.getHolder().getSurface().isValid()) {
            return null;
        }
        final Semaphore semaphore = new Semaphore(0);
        Bitmap bitmapCreateBitmap = Bitmap.createBitmap(this.e.getWidth(), this.e.getHeight(), Bitmap.Config.ARGB_8888);
        HandlerThread handlerThread = new HandlerThread("pixelCopyRequest Thread");
        handlerThread.start();
        PixelCopy.request(this.e, bitmapCreateBitmap, new PixelCopy.OnPixelCopyFinishedListener() { // from class: androidx.camera.view.o
            @Override // android.view.PixelCopy.OnPixelCopyFinishedListener
            public final void onPixelCopyFinished(int i) {
                if (i == 0) {
                    AbstractC3053s1.f(3, "SurfaceViewImpl");
                } else {
                    AbstractC3053s1.c("SurfaceViewImpl", "PreviewView.SurfaceViewImplementation.getBitmap() failed with error " + i);
                }
                semaphore.release();
            }
        }, new Handler(handlerThread.getLooper()));
        try {
            if (!semaphore.tryAcquire(1, 100L, TimeUnit.MILLISECONDS)) {
                AbstractC3053s1.c("SurfaceViewImpl", "Timed out while trying to acquire screenshot.");
            }
            return bitmapCreateBitmap;
        } catch (InterruptedException e) {
            AbstractC3053s1.d("SurfaceViewImpl", "Interrupted while trying to acquire screenshot.", e);
            return bitmapCreateBitmap;
        } finally {
            handlerThread.quitSafely();
        }
    }

    @Override // androidx.camera.view.j
    public final void f() {
    }

    @Override // androidx.camera.view.j
    public final void g() {
    }

    @Override // androidx.camera.view.j
    public final void h(j0 j0Var, T t) {
        SurfaceView surfaceView = this.e;
        boolean zEquals = Objects.equals((Size) this.b, j0Var.b);
        if (surfaceView == null || !zEquals) {
            Size size = j0Var.b;
            this.b = size;
            FrameLayout frameLayout = (FrameLayout) this.c;
            size.getClass();
            SurfaceView surfaceView2 = new SurfaceView(frameLayout.getContext());
            this.e = surfaceView2;
            surfaceView2.setLayoutParams(new FrameLayout.LayoutParams(((Size) this.b).getWidth(), ((Size) this.b).getHeight()));
            frameLayout.removeAllViews();
            frameLayout.addView(this.e);
            this.e.getHolder().addCallback(this.f);
        }
        Executor executorD = androidx.core.content.c.d(this.e.getContext());
        j0Var.j.a(new RunnableC0041m(t, 25), executorD);
        this.e.post(new RunnableC0130g(this, j0Var, t, 9));
    }

    @Override // androidx.camera.view.j
    public final com.google.common.util.concurrent.e l() {
        return androidx.camera.core.impl.utils.futures.k.c;
    }
}
