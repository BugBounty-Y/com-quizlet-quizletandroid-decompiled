package androidx.constraintlayout.compose;

import android.os.Handler;
import androidx.camera.camera2.internal.C0132i;
import androidx.compose.runtime.InterfaceC0834w0;
import androidx.compose.runtime.snapshots.v;
import java.util.ArrayList;

/* loaded from: classes.dex */
public final class i implements InterfaceC0834w0 {
    public final g a;
    public Handler b;
    public final v c = new v(new h(this, 0));
    public boolean d = true;
    public final h e = new h(this, 1);
    public final ArrayList f = new ArrayList();

    public i(g gVar) {
        this.a = gVar;
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void a() {
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void b() {
        v vVar = this.c;
        C0132i c0132i = vVar.h;
        if (c0132i != null) {
            c0132i.f();
        }
        vVar.b();
    }

    @Override // androidx.compose.runtime.InterfaceC0834w0
    public final void d() {
        this.c.e();
    }
}
