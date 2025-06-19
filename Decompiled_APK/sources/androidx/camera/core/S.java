package androidx.camera.core;

import androidx.activity.RunnableC0041m;
import androidx.camera.core.impl.AbstractC0171j;
import androidx.camera.core.impl.InterfaceC0177p;
import androidx.camera.core.impl.q0;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class S extends AbstractC0171j {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ S(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.camera.core.impl.AbstractC0171j
    public void b(int i, InterfaceC0177p interfaceC0177p) {
        switch (this.a) {
            case 0:
                T t = (T) this.b;
                synchronized (t.a) {
                    try {
                        if (t.e) {
                            return;
                        }
                        t.i.put(interfaceC0177p.a(), new androidx.camera.core.internal.c(interfaceC0177p));
                        t.f();
                        return;
                    } finally {
                    }
                }
            case 1:
            default:
                return;
            case 2:
                Iterator it2 = ((androidx.camera.core.streamsharing.g) this.b).a.iterator();
                while (it2.hasNext()) {
                    q0 q0Var = ((l0) it2.next()).m;
                    Iterator it3 = q0Var.g.d.iterator();
                    while (it3.hasNext()) {
                        ((AbstractC0171j) it3.next()).b(i, new com.quizlet.data.interactor.course.c(interfaceC0177p, q0Var.g.f, -1L));
                    }
                }
                return;
        }
    }

    @Override // androidx.camera.core.impl.AbstractC0171j
    public void d(int i) {
        switch (this.a) {
            case 1:
                com.google.android.gms.internal.mlkit_vision_barcode.T.e().execute(new RunnableC0041m(this, 11));
                break;
        }
    }
}
