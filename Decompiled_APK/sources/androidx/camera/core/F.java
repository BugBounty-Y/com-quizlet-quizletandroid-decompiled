package androidx.camera.core;

import androidx.activity.RunnableC0041m;
import java.lang.ref.WeakReference;

/* loaded from: classes.dex */
public final /* synthetic */ class F implements InterfaceC0198v {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ F(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.camera.core.InterfaceC0198v
    public final void a(AbstractC0199w abstractC0199w) {
        InterfaceC0198v interfaceC0198v;
        switch (this.a) {
            case 0:
                H h = (H) ((WeakReference) ((G) this.b).e).get();
                if (h != null) {
                    h.t.execute(new RunnableC0041m(h, 9));
                    return;
                }
                return;
            default:
                a0 a0Var = (a0) this.b;
                synchronized (a0Var.c) {
                    try {
                        int i = a0Var.a - 1;
                        a0Var.a = i;
                        if (a0Var.b && i == 0) {
                            a0Var.close();
                        }
                        interfaceC0198v = (InterfaceC0198v) a0Var.f;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                if (interfaceC0198v != null) {
                    interfaceC0198v.a(abstractC0199w);
                    return;
                }
                return;
        }
    }
}
