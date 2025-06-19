package androidx.camera.camera2.impl;

import android.hardware.camera2.CaptureRequest;
import androidx.camera.core.A;
import androidx.camera.core.InterfaceC0197u;
import androidx.camera.core.impl.A0;
import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0162c;
import androidx.camera.core.impl.C0163c0;
import androidx.camera.core.impl.G;
import androidx.camera.core.impl.M;
import androidx.camera.core.impl.W;
import androidx.camera.core.impl.X;
import androidx.camera.core.impl.z0;
import androidx.camera.core.internal.k;
import java.util.UUID;

/* loaded from: classes.dex */
public final class a implements InterfaceC0197u, z0 {
    public final /* synthetic */ int a;
    public final X b;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public a(int i) {
        this(X.b());
        this.a = i;
        switch (i) {
            case 1:
                break;
            default:
                this.b = X.b();
                break;
        }
    }

    public void a(CaptureRequest.Key key, Object obj) {
        G g = G.b;
        this.b.l(b.U(key), g, obj);
    }

    @Override // androidx.camera.core.InterfaceC0197u
    public final W q() {
        switch (this.a) {
            case 0:
                throw null;
            default:
                return this.b;
        }
    }

    @Override // androidx.camera.core.impl.z0
    public A0 s() {
        return new M(C0163c0.a(this.b));
    }

    public a(X x) {
        Object objE;
        this.a = 1;
        this.b = x;
        Object objE2 = null;
        try {
            objE = x.e(k.A0);
        } catch (IllegalArgumentException unused) {
            objE = null;
        }
        Class cls = (Class) objE;
        if (cls != null && !cls.equals(A.class)) {
            throw new IllegalArgumentException("Invalid target class configuration for " + this + ": " + cls);
        }
        this.b.m(A0.v0, C0.c);
        C0162c c0162c = k.A0;
        X x2 = this.b;
        x2.m(c0162c, A.class);
        try {
            objE2 = x2.e(k.z0);
        } catch (IllegalArgumentException unused2) {
        }
        if (objE2 == null) {
            x2.m(k.z0, A.class.getCanonicalName() + "-" + UUID.randomUUID());
        }
    }
}
