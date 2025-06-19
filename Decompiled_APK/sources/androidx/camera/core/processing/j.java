package androidx.camera.core.processing;

import android.util.Size;
import androidx.activity.RunnableC0041m;
import androidx.camera.camera2.internal.C0132i;
import androidx.camera.core.impl.J;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;

/* loaded from: classes.dex */
public final class j extends J {
    public final androidx.concurrent.futures.l o;
    public androidx.concurrent.futures.i p;
    public J q;
    public l r;

    public j(Size size, int i) {
        super(size, i);
        this.o = Y5.b(new C0132i(this, 7));
    }

    @Override // androidx.camera.core.impl.J
    public final void a() {
        super.a();
        S.g(new g(this, 2));
    }

    @Override // androidx.camera.core.impl.J
    public final com.google.common.util.concurrent.e f() {
        return this.o;
    }

    public final boolean g(J j, Runnable runnable) {
        boolean z;
        S.d();
        j.getClass();
        J j2 = this.q;
        if (j2 == j) {
            return false;
        }
        AbstractC3242q6.h("A different provider has been set. To change the provider, call SurfaceEdge#invalidate before calling SurfaceEdge#setProvider", j2 == null);
        Size size = this.h;
        Size size2 = j.h;
        AbstractC3242q6.c("The provider's size(" + size + ") must match the parent(" + size2 + ")", size.equals(size2));
        int i = j.i;
        int i2 = this.i;
        AbstractC3242q6.c(android.support.v4.media.session.a.j("The provider's format(", i2, ") must match the parent(", ")", i), i2 == i);
        synchronized (this.a) {
            z = this.c;
        }
        AbstractC3242q6.h("The parent is closed. Call SurfaceEdge#invalidate() before setting a new provider.", !z);
        this.q = j;
        androidx.camera.core.impl.utils.futures.i.e(true, j.c(), this.p, T.a());
        j.d();
        androidx.camera.core.impl.utils.futures.i.d(this.e).a(new RunnableC0041m(j, 21), T.a());
        androidx.camera.core.impl.utils.futures.i.d(j.g).a(runnable, T.e());
        return true;
    }
}
