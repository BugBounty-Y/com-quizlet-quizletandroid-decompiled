package androidx.camera.core.processing;

import android.graphics.Matrix;
import android.graphics.Rect;
import androidx.activity.RunnableC0041m;
import androidx.camera.core.C0187j;
import androidx.camera.core.c0;
import androidx.camera.core.g0;
import androidx.camera.core.i0;
import androidx.camera.core.impl.C0168g;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import androidx.camera.core.impl.InterfaceC0185y;
import androidx.camera.core.j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class k {
    public final int a;
    public final Matrix b;
    public final boolean c;
    public final Rect d;
    public final boolean e;
    public final int f;
    public final C0168g g;
    public int h;
    public int i;
    public j0 k;
    public j l;
    public boolean j = false;
    public final HashSet m = new HashSet();
    public boolean n = false;
    public final ArrayList o = new ArrayList();

    public k(int i, int i2, C0168g c0168g, Matrix matrix, boolean z, Rect rect, int i3, int i4, boolean z2) {
        this.f = i;
        this.a = i2;
        this.g = c0168g;
        this.b = matrix;
        this.c = z;
        this.d = rect;
        this.i = i3;
        this.h = i4;
        this.e = z2;
        this.l = new j(c0168g.a, i2);
    }

    public final void a() {
        AbstractC3242q6.h("Edge is already closed.", !this.n);
    }

    public final void b() {
        S.d();
        this.l.a();
        this.n = true;
    }

    public final j0 c(InterfaceC0185y interfaceC0185y, boolean z) {
        S.d();
        a();
        C0168g c0168g = this.g;
        j0 j0Var = new j0(c0168g.a, interfaceC0185y, z, c0168g.b, new f(this, 0));
        try {
            g0 g0Var = j0Var.k;
            j jVar = this.l;
            Objects.requireNonNull(jVar);
            if (jVar.g(g0Var, new g(jVar, 0))) {
                androidx.camera.core.impl.utils.futures.i.d(jVar.e).a(new RunnableC0041m(g0Var, 20), T.a());
            }
            this.k = j0Var;
            e();
            return j0Var;
        } catch (DeferrableSurface$SurfaceClosedException e) {
            throw new AssertionError("Surface is somehow already closed", e);
        } catch (RuntimeException e2) {
            j0Var.c();
            throw e2;
        }
    }

    public final void d() {
        boolean z;
        S.d();
        a();
        j jVar = this.l;
        jVar.getClass();
        S.d();
        if (jVar.q == null) {
            synchronized (jVar.a) {
                z = jVar.c;
            }
            if (!z) {
                return;
            }
        }
        this.j = false;
        this.l.a();
        this.l = new j(this.g.a, this.a);
        Iterator it2 = this.m.iterator();
        while (it2.hasNext()) {
            ((Runnable) it2.next()).run();
        }
    }

    public final void e() {
        i0 i0Var;
        Executor executor;
        S.d();
        C0187j c0187j = new C0187j(this.d, this.i, this.h, this.c, this.b, this.e);
        j0 j0Var = this.k;
        if (j0Var != null) {
            synchronized (j0Var.a) {
                j0Var.l = c0187j;
                i0Var = j0Var.m;
                executor = j0Var.n;
            }
            if (i0Var != null && executor != null) {
                executor.execute(new c0(i0Var, c0187j, 0));
            }
        }
        Iterator it2 = this.o.iterator();
        while (it2.hasNext()) {
            ((androidx.core.util.a) it2.next()).accept(c0187j);
        }
    }
}
