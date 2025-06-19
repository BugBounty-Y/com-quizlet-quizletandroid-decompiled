package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final class D {
    public final androidx.work.impl.model.n a;
    public C1721Kc b;
    public final com.quizlet.data.repository.user.a c;
    public final C3056t d;

    public D() {
        androidx.work.impl.model.n nVar = new androidx.work.impl.model.n();
        this.a = nVar;
        this.b = ((C1721Kc) nVar.b).g();
        this.c = new com.quizlet.data.repository.user.a(6);
        this.d = new C3056t(2);
        final int i = 0;
        Callable callable = new Callable(this) { // from class: com.google.android.gms.internal.measurement.a
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // java.util.concurrent.Callable
            public final Object call() {
                switch (i) {
                    case 0:
                        return new E1(this.b.d);
                    default:
                        return new E1(this.b.c);
                }
            }
        };
        C3005i2 c3005i2 = (C3005i2) nVar.d;
        ((HashMap) c3005i2.a).put("internal.registerCallback", callable);
        final int i2 = 1;
        ((HashMap) c3005i2.a).put("internal.eventLogger", new Callable(this) { // from class: com.google.android.gms.internal.measurement.a
            public final /* synthetic */ D b;

            {
                this.b = this;
            }

            @Override // java.util.concurrent.Callable
            public final Object call() {
                switch (i2) {
                    case 0:
                        return new E1(this.b.d);
                    default:
                        return new E1(this.b.c);
                }
            }
        });
    }

    public final void a(C3034o1 c3034o1) {
        AbstractC2997h abstractC2997h;
        try {
            androidx.work.impl.model.n nVar = this.a;
            this.b = ((C1721Kc) nVar.b).g();
            if (nVar.k(this.b, (C3039p1[]) c3034o1.o().toArray(new C3039p1[0])) instanceof C2987f) {
                throw new IllegalStateException("Program loading failed");
            }
            for (C3029n1 c3029n1 : c3034o1.n().p()) {
                InterfaceC2975c2 interfaceC2975c2O = c3029n1.o();
                String strN = c3029n1.n();
                Iterator it2 = interfaceC2975c2O.iterator();
                while (it2.hasNext()) {
                    InterfaceC3027n interfaceC3027nK = nVar.k(this.b, (C3039p1) it2.next());
                    if (!(interfaceC3027nK instanceof C3012k)) {
                        throw new IllegalArgumentException("Invalid rule definition");
                    }
                    C1721Kc c1721Kc = this.b;
                    if (c1721Kc.o(strN)) {
                        InterfaceC3027n interfaceC3027nL = c1721Kc.l(strN);
                        if (!(interfaceC3027nL instanceof AbstractC2997h)) {
                            throw new IllegalStateException("Invalid function name: ".concat(String.valueOf(strN)));
                        }
                        abstractC2997h = (AbstractC2997h) interfaceC3027nL;
                    } else {
                        abstractC2997h = null;
                    }
                    if (abstractC2997h == null) {
                        throw new IllegalStateException("Rule function is undefined: ".concat(String.valueOf(strN)));
                    }
                    abstractC2997h.d(this.b, Collections.singletonList(interfaceC3027nK));
                }
            }
        } catch (Throwable th) {
            throw new zzd(th);
        }
    }

    public final boolean b(C2967b c2967b) throws zzd {
        com.quizlet.data.repository.user.a aVar = this.c;
        try {
            aVar.b = c2967b;
            aVar.c = c2967b.clone();
            ((ArrayList) aVar.d).clear();
            ((C1721Kc) this.a.c).n("runtime.counter", new C2992g(Double.valueOf(0.0d)));
            this.d.c(this.b.g(), aVar);
            if (((C2967b) aVar.c).equals((C2967b) aVar.b)) {
                return !((ArrayList) aVar.d).isEmpty();
            }
            return true;
        } catch (Throwable th) {
            throw new zzd(th);
        }
    }
}
