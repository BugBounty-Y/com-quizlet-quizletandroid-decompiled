package androidx.camera.camera2.internal;

import androidx.camera.core.impl.C0;
import androidx.camera.core.impl.C0165d0;
import androidx.camera.core.impl.C0168g;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.ExecutionException;

/* loaded from: classes.dex */
public final /* synthetic */ class Z implements androidx.camera.core.impl.o0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ Z(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // androidx.camera.core.impl.o0
    public final void a(androidx.camera.core.impl.q0 q0Var) {
        switch (this.a) {
            case 0:
                c0 c0Var = (c0) this.b;
                c0Var.c = c0Var.m();
                C0139p c0139p = (C0139p) c0Var.f;
                if (c0139p != null) {
                    C c = c0139p.b;
                    c.getClass();
                    try {
                        if (((Boolean) Y5.b(new C0139p(c, 2)).b.get()).booleanValue()) {
                            c0 c0Var2 = c.w;
                            androidx.camera.core.impl.q0 q0Var2 = (androidx.camera.core.impl.q0) c0Var2.c;
                            c.c.execute(new RunnableC0141s(c, C.w(c0Var2), q0Var2, (b0) c0Var2.d, null, Collections.singletonList(C0.f), 0));
                            return;
                        }
                        return;
                    } catch (InterruptedException | ExecutionException e) {
                        throw new RuntimeException("Unable to check if MeteringRepeating is attached.", e);
                    }
                }
                return;
            case 1:
                androidx.camera.core.A a = (androidx.camera.core.A) this.b;
                if (a.b() == null) {
                    return;
                }
                com.google.android.gms.internal.mlkit_vision_barcode.S.d();
                androidx.camera.core.impl.n0 n0Var = a.t;
                if (n0Var != null) {
                    n0Var.b();
                    a.t = null;
                }
                androidx.camera.core.g0 g0Var = a.s;
                if (g0Var != null) {
                    g0Var.a();
                    a.s = null;
                }
                a.o.c();
                a.d();
                androidx.camera.core.impl.M m = (androidx.camera.core.impl.M) a.f;
                C0168g c0168g = a.g;
                c0168g.getClass();
                androidx.camera.core.impl.m0 m0VarB = a.B(m, c0168g);
                a.r = m0VarB;
                Object[] objArr = {m0VarB.c()};
                ArrayList arrayList = new ArrayList(1);
                Object obj = objArr[0];
                Objects.requireNonNull(obj);
                arrayList.add(obj);
                a.A(Collections.unmodifiableList(arrayList));
                a.n();
                return;
            case 2:
                androidx.camera.core.L l = (androidx.camera.core.L) this.b;
                if (l.b() == null) {
                    return;
                }
                androidx.camera.core.imagecapture.d dVar = l.u;
                dVar.getClass();
                com.google.android.gms.internal.mlkit_vision_barcode.S.d();
                dVar.d = true;
                l.B(true);
                String strD = l.d();
                androidx.camera.core.impl.N n = (androidx.camera.core.impl.N) l.f;
                C0168g c0168g2 = l.g;
                c0168g2.getClass();
                androidx.camera.core.impl.m0 m0VarC = l.C(strD, n, c0168g2);
                l.s = m0VarC;
                Object[] objArr2 = {m0VarC.c()};
                ArrayList arrayList2 = new ArrayList(1);
                Object obj2 = objArr2[0];
                Objects.requireNonNull(obj2);
                arrayList2.add(obj2);
                l.A(Collections.unmodifiableList(arrayList2));
                l.n();
                androidx.camera.core.imagecapture.d dVar2 = l.u;
                dVar2.getClass();
                com.google.android.gms.internal.mlkit_vision_barcode.S.d();
                dVar2.d = false;
                dVar2.c();
                return;
            case 3:
                androidx.camera.core.X x = (androidx.camera.core.X) this.b;
                if (x.b() == null) {
                    return;
                }
                x.D((C0165d0) x.f, x.g);
                x.n();
                return;
            default:
                Iterator it2 = ((androidx.camera.core.impl.p0) this.b).l.iterator();
                while (it2.hasNext()) {
                    ((androidx.camera.core.impl.o0) it2.next()).a(q0Var);
                }
                return;
        }
    }
}
