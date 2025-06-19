package androidx.camera.view;

import android.util.Size;
import android.view.Surface;
import android.view.SurfaceHolder;
import androidx.camera.camera2.internal.T;
import androidx.camera.core.j0;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.Objects;

/* loaded from: classes.dex */
public final class p implements SurfaceHolder.Callback {
    public Size a;
    public j0 b;
    public j0 c;
    public T d;
    public Size e;
    public boolean f = false;
    public boolean g = false;
    public final /* synthetic */ q h;

    public p(q qVar) {
        this.h = qVar;
    }

    public final boolean a() {
        q qVar = this.h;
        Surface surface = qVar.e.getHolder().getSurface();
        if (this.f || this.b == null || !Objects.equals(this.a, this.e)) {
            return false;
        }
        AbstractC3053s1.f(3, "SurfaceViewImpl");
        T t = this.d;
        j0 j0Var = this.b;
        Objects.requireNonNull(j0Var);
        j0Var.a(surface, androidx.core.content.c.d(qVar.e.getContext()), new androidx.camera.core.imagecapture.c(t, 2));
        this.f = true;
        qVar.a = true;
        qVar.i();
        return true;
    }

    @Override // android.view.SurfaceHolder.Callback
    public final void surfaceChanged(SurfaceHolder surfaceHolder, int i, int i2, int i3) {
        AbstractC3053s1.f(3, "SurfaceViewImpl");
        this.e = new Size(i2, i3);
        a();
    }

    @Override // android.view.SurfaceHolder.Callback
    public final void surfaceCreated(SurfaceHolder surfaceHolder) {
        j0 j0Var;
        AbstractC3053s1.f(3, "SurfaceViewImpl");
        if (!this.g || (j0Var = this.c) == null) {
            return;
        }
        j0Var.c();
        j0Var.i.b(null);
        this.c = null;
        this.g = false;
    }

    @Override // android.view.SurfaceHolder.Callback
    public final void surfaceDestroyed(SurfaceHolder surfaceHolder) {
        AbstractC3053s1.f(3, "SurfaceViewImpl");
        if (this.f) {
            j0 j0Var = this.b;
            if (j0Var != null) {
                Objects.toString(j0Var);
                AbstractC3053s1.f(3, "SurfaceViewImpl");
                this.b.k.a();
            }
        } else {
            j0 j0Var2 = this.b;
            if (j0Var2 != null) {
                Objects.toString(j0Var2);
                AbstractC3053s1.f(3, "SurfaceViewImpl");
                this.b.c();
            }
        }
        this.g = true;
        j0 j0Var3 = this.b;
        if (j0Var3 != null) {
            this.c = j0Var3;
        }
        this.f = false;
        this.b = null;
        this.d = null;
        this.e = null;
        this.a = null;
    }
}
