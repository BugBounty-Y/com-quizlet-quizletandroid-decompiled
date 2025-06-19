package androidx.lifecycle;

import java.lang.ref.WeakReference;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends C {
    public final boolean b;
    public androidx.arch.core.internal.a c;
    public B d;
    public final WeakReference e;
    public int f;
    public boolean g;
    public boolean h;
    public final ArrayList i;
    public final kotlinx.coroutines.flow.s0 j;

    public L(J provider) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        this.a = new A0();
        this.b = true;
        this.c = new androidx.arch.core.internal.a();
        B b = B.b;
        this.d = b;
        this.i = new ArrayList();
        this.e = new WeakReference(provider);
        this.j = kotlinx.coroutines.flow.e0.c(b);
    }

    @Override // androidx.lifecycle.C
    public final void a(I object) {
        H c1252m;
        Object obj;
        J j;
        ArrayList arrayList = this.i;
        Intrinsics.checkNotNullParameter(object, "observer");
        d("addObserver");
        B b = this.d;
        B initialState = B.a;
        if (b != initialState) {
            initialState = B.b;
        }
        Intrinsics.checkNotNullParameter(initialState, "initialState");
        K k = new K();
        Intrinsics.d(object);
        HashMap map = N.a;
        Intrinsics.checkNotNullParameter(object, "object");
        boolean z = object instanceof H;
        boolean z2 = object instanceof InterfaceC1250k;
        if (z && z2) {
            c1252m = new C1252m((InterfaceC1250k) object, (H) object);
        } else if (z2) {
            c1252m = new C1252m((InterfaceC1250k) object, (H) null);
        } else if (z) {
            c1252m = (H) object;
        } else {
            Class<?> cls = object.getClass();
            if (N.c(cls) == 2) {
                Object obj2 = N.b.get(cls);
                Intrinsics.d(obj2);
                List list = (List) obj2;
                if (list.size() == 1) {
                    N.a((Constructor) list.get(0), object);
                    throw null;
                }
                int size = list.size();
                InterfaceC1260v[] interfaceC1260vArr = new InterfaceC1260v[size];
                if (size > 0) {
                    N.a((Constructor) list.get(0), object);
                    throw null;
                }
                c1252m = new C1246g(interfaceC1260vArr);
            } else {
                c1252m = new C1252m(object);
            }
        }
        k.b = c1252m;
        k.a = initialState;
        androidx.arch.core.internal.a aVar = this.c;
        androidx.arch.core.internal.c cVarA = aVar.a(object);
        if (cVarA != null) {
            obj = cVarA.b;
        } else {
            HashMap map2 = aVar.e;
            androidx.arch.core.internal.c cVar = new androidx.arch.core.internal.c(object, k);
            aVar.d++;
            androidx.arch.core.internal.c cVar2 = aVar.b;
            if (cVar2 == null) {
                aVar.a = cVar;
                aVar.b = cVar;
            } else {
                cVar2.c = cVar;
                cVar.d = cVar2;
                aVar.b = cVar;
            }
            map2.put(object, cVar);
            obj = null;
        }
        if (((K) obj) == null && (j = (J) this.e.get()) != null) {
            boolean z3 = this.f != 0 || this.g;
            B bC = c(object);
            this.f++;
            while (k.a.compareTo(bC) < 0 && this.c.e.containsKey(object)) {
                arrayList.add(k.a);
                C1263y c1263y = A.Companion;
                B state = k.a;
                c1263y.getClass();
                Intrinsics.checkNotNullParameter(state, "state");
                int iOrdinal = state.ordinal();
                A a = iOrdinal != 1 ? iOrdinal != 2 ? iOrdinal != 3 ? null : A.ON_RESUME : A.ON_START : A.ON_CREATE;
                if (a == null) {
                    throw new IllegalStateException("no event up from " + k.a);
                }
                k.a(j, a);
                arrayList.remove(arrayList.size() - 1);
                bC = c(object);
            }
            if (!z3) {
                h();
            }
            this.f--;
        }
    }

    @Override // androidx.lifecycle.C
    public final void b(I observer) {
        Intrinsics.checkNotNullParameter(observer, "observer");
        d("removeObserver");
        this.c.b(observer);
    }

    public final B c(I i) {
        HashMap map = this.c.e;
        androidx.arch.core.internal.c cVar = map.containsKey(i) ? ((androidx.arch.core.internal.c) map.get(i)).d : null;
        B state1 = cVar != null ? ((K) cVar.b).a : null;
        ArrayList arrayList = this.i;
        B b = arrayList.isEmpty() ? null : (B) android.support.v4.media.session.a.e(1, arrayList);
        B state12 = this.d;
        Intrinsics.checkNotNullParameter(state12, "state1");
        if (state1 == null || state1.compareTo(state12) >= 0) {
            state1 = state12;
        }
        Intrinsics.checkNotNullParameter(state1, "state1");
        return (b == null || b.compareTo(state1) >= 0) ? state1 : b;
    }

    public final void d(String str) {
        if (this.b && !androidx.arch.core.executor.b.p().a.q()) {
            throw new IllegalStateException(android.support.v4.media.session.a.B("Method ", str, " must be called on the main thread").toString());
        }
    }

    public final void e(A event) {
        Intrinsics.checkNotNullParameter(event, "event");
        d("handleLifecycleEvent");
        f(event.a());
    }

    public final void f(B next) {
        if (this.d == next) {
            return;
        }
        J j = (J) this.e.get();
        B current = this.d;
        Intrinsics.checkNotNullParameter(current, "current");
        Intrinsics.checkNotNullParameter(next, "next");
        if (current == B.b && next == B.a) {
            throw new IllegalStateException(("State must be at least '" + B.c + "' to be moved to '" + next + "' in component " + j).toString());
        }
        B b = B.a;
        if (current == b && current != next) {
            throw new IllegalStateException(("State is '" + b + "' and cannot be moved to `" + next + "` in component " + j).toString());
        }
        this.d = next;
        if (this.g || this.f != 0) {
            this.h = true;
            return;
        }
        this.g = true;
        h();
        this.g = false;
        if (this.d == b) {
            this.c = new androidx.arch.core.internal.a();
        }
    }

    public final void g(B state) {
        Intrinsics.checkNotNullParameter(state, "state");
        d("setCurrentState");
        f(state);
    }

    /* JADX WARN: Code restructure failed: missing block: B:11:0x0030, code lost:
    
        r12.h = false;
        r12.j.l(r12.d);
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0039, code lost:
    
        return;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h() {
        /*
            Method dump skipped, instructions count: 425
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.lifecycle.L.h():void");
    }
}
