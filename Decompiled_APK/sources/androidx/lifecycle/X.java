package androidx.lifecycle;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class X extends Y {
    public final /* synthetic */ int l;
    public Object m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X(Object obj) {
        super(obj);
        this.l = 0;
    }

    @Override // androidx.lifecycle.T
    public void f(J owner, Z observer) {
        switch (this.l) {
            case 1:
                Intrinsics.checkNotNullParameter(owner, "owner");
                Intrinsics.checkNotNullParameter(observer, "observer");
                if (e()) {
                    timber.log.c.a.o("Multiple observers registered but only one will be notified of changes.", new Object[0]);
                }
                super.f(owner, new com.onetrust.otpublishers.headless.UI.fragment.z(2, this, observer));
                break;
            default:
                super.f(owner, observer);
                break;
        }
    }

    @Override // androidx.lifecycle.T
    public void h() {
        switch (this.l) {
            case 0:
                Iterator it2 = ((androidx.arch.core.internal.f) this.m).iterator();
                while (true) {
                    androidx.arch.core.internal.b bVar = (androidx.arch.core.internal.b) it2;
                    if (!bVar.hasNext()) {
                        break;
                    } else {
                        ((W) ((Map.Entry) bVar.next()).getValue()).b();
                    }
                }
        }
    }

    @Override // androidx.lifecycle.T
    public void i() {
        switch (this.l) {
            case 0:
                Iterator it2 = ((androidx.arch.core.internal.f) this.m).iterator();
                while (true) {
                    androidx.arch.core.internal.b bVar = (androidx.arch.core.internal.b) it2;
                    if (!bVar.hasNext()) {
                        break;
                    } else {
                        W w = (W) ((Map.Entry) bVar.next()).getValue();
                        w.a.k(w);
                    }
                }
        }
    }

    @Override // androidx.lifecycle.T
    public void j(Object obj) {
        switch (this.l) {
            case 1:
                ((AtomicBoolean) this.m).set(true);
                super.j(obj);
                break;
            default:
                super.j(obj);
                break;
        }
    }

    @Override // androidx.lifecycle.T
    public void l(Object obj) {
        switch (this.l) {
            case 1:
                ((AtomicBoolean) this.m).set(true);
                super.l(obj);
                break;
            default:
                super.l(obj);
                break;
        }
    }

    public void m(T t, Z z) {
        Object obj;
        if (t == null) {
            throw new NullPointerException("source cannot be null");
        }
        W w = new W(t, z);
        androidx.arch.core.internal.f fVar = (androidx.arch.core.internal.f) this.m;
        androidx.arch.core.internal.c cVarA = fVar.a(t);
        if (cVarA != null) {
            obj = cVarA.b;
        } else {
            androidx.arch.core.internal.c cVar = new androidx.arch.core.internal.c(t, w);
            fVar.d++;
            androidx.arch.core.internal.c cVar2 = fVar.b;
            if (cVar2 == null) {
                fVar.a = cVar;
                fVar.b = cVar;
            } else {
                cVar2.c = cVar;
                cVar.d = cVar2;
                fVar.b = cVar;
            }
            obj = null;
        }
        W w2 = (W) obj;
        if (w2 != null && w2.b != z) {
            throw new IllegalArgumentException("This source was already added with the different observer");
        }
        if (w2 == null && e()) {
            w.b();
        }
    }

    public X(int i) {
        this.l = i;
        switch (i) {
            case 1:
                this.m = new AtomicBoolean(false);
                break;
            default:
                this.m = new androidx.arch.core.internal.f();
                break;
        }
    }
}
