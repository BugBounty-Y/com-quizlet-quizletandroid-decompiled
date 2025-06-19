package kotlinx.coroutines.selects;

import androidx.compose.ui.node.B;
import com.android.billingclient.api.C1472a;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.InterfaceC5024j;
import kotlinx.coroutines.InterfaceC5026k;
import kotlinx.coroutines.J0;
import kotlinx.coroutines.internal.q;

/* loaded from: classes3.dex */
public final class e implements InterfaceC5024j, f, J0 {
    public static final /* synthetic */ AtomicReferenceFieldUpdater f = AtomicReferenceFieldUpdater.newUpdater(e.class, Object.class, "state$volatile");
    public final CoroutineContext a;
    public Object c;
    private volatile /* synthetic */ Object state$volatile = h.a;
    public ArrayList b = new ArrayList(2);
    public int d = -1;
    public Object e = h.d;

    public e(CoroutineContext coroutineContext) {
        this.a = coroutineContext;
    }

    @Override // kotlinx.coroutines.J0
    public final void a(q qVar, int i) {
        this.c = qVar;
        this.d = i;
    }

    @Override // kotlinx.coroutines.InterfaceC5024j
    public final void b(Throwable th) {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
            Object obj = atomicReferenceFieldUpdater.get(this);
            if (obj == h.b) {
                return;
            }
            C1472a c1472a = h.c;
            while (!atomicReferenceFieldUpdater.compareAndSet(this, obj, c1472a)) {
                if (atomicReferenceFieldUpdater.get(this) != obj) {
                    break;
                }
            }
            ArrayList arrayList = this.b;
            if (arrayList == null) {
                return;
            }
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((c) it2.next()).a();
            }
            this.e = h.d;
            this.b = null;
            return;
        }
    }

    public final Object c(kotlin.coroutines.jvm.internal.c cVar) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
        Object obj = atomicReferenceFieldUpdater.get(this);
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.selects.SelectImplementation.ClauseData<R of kotlinx.coroutines.selects.SelectImplementation>");
        c cVar2 = (c) obj;
        Object obj2 = this.e;
        ArrayList arrayList = this.b;
        if (arrayList != null) {
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                c cVar3 = (c) it2.next();
                if (cVar3 != cVar2) {
                    cVar3.a();
                }
            }
            atomicReferenceFieldUpdater.set(this, h.b);
            this.e = h.d;
            this.b = null;
        }
        Object objInvoke = cVar2.c.invoke(cVar2.a, cVar2.d, obj2);
        C1472a c1472a = h.e;
        kotlin.coroutines.h hVar = cVar2.e;
        return cVar2.d == c1472a ? ((Function1) hVar).invoke(cVar) : ((Function2) hVar).invoke(objInvoke, cVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object d(kotlin.coroutines.jvm.internal.c r10) throws kotlinx.coroutines.DispatchException {
        /*
            r9 = this;
            boolean r0 = r10 instanceof kotlinx.coroutines.selects.d
            if (r0 == 0) goto L13
            r0 = r10
            kotlinx.coroutines.selects.d r0 = (kotlinx.coroutines.selects.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            kotlinx.coroutines.selects.d r0 = new kotlinx.coroutines.selects.d
            r0.<init>(r9, r10)
        L18:
            java.lang.Object r10 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 2
            r5 = 1
            if (r2 == 0) goto L3a
            if (r2 == r5) goto L33
            if (r2 != r4) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r10)
            return r10
        L2b:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r0)
            throw r10
        L33:
            kotlinx.coroutines.selects.e r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r10)
            goto Lbd
        L3a:
            androidx.glance.appwidget.protobuf.Z.e(r10)
            r0.j = r9
            r0.m = r5
            kotlinx.coroutines.l r10 = new kotlinx.coroutines.l
            kotlin.coroutines.h r2 = kotlin.coroutines.intrinsics.h.b(r0)
            r10.<init>(r5, r2)
            r10.r()
        L4d:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r2 = kotlinx.coroutines.selects.e.f
            java.lang.Object r6 = r2.get(r9)
            com.android.billingclient.api.a r7 = kotlinx.coroutines.selects.h.a
            if (r6 != r7) goto L68
        L57:
            boolean r7 = r2.compareAndSet(r9, r6, r10)
            if (r7 == 0) goto L61
            r10.v(r9)
            goto La7
        L61:
            java.lang.Object r7 = r2.get(r9)
            if (r7 == r6) goto L57
            goto L4d
        L68:
            boolean r8 = r6 instanceof java.util.List
            if (r8 == 0) goto L99
        L6c:
            boolean r8 = r2.compareAndSet(r9, r6, r7)
            if (r8 == 0) goto L92
            java.lang.Iterable r6 = (java.lang.Iterable) r6
            java.util.Iterator r2 = r6.iterator()
        L78:
            boolean r6 = r2.hasNext()
            if (r6 == 0) goto L4d
            java.lang.Object r6 = r2.next()
            kotlinx.coroutines.selects.c r6 = r9.e(r6)
            kotlin.jvm.internal.Intrinsics.d(r6)
            r6.f = r3
            r7 = -1
            r6.g = r7
            r9.f(r6, r5)
            goto L78
        L92:
            java.lang.Object r8 = r2.get(r9)
            if (r8 == r6) goto L6c
            goto L4d
        L99:
            boolean r2 = r6 instanceof kotlinx.coroutines.selects.c
            if (r2 == 0) goto Lc9
            kotlin.Unit r2 = kotlin.Unit.a
            kotlinx.coroutines.selects.c r6 = (kotlinx.coroutines.selects.c) r6
            r6.getClass()
            r10.m(r2, r3)
        La7:
            java.lang.Object r10 = r10.q()
            kotlin.coroutines.intrinsics.a r2 = kotlin.coroutines.intrinsics.a.a
            if (r10 != r2) goto Lb4
            java.lang.String r5 = "frame"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r0, r5)
        Lb4:
            if (r10 != r2) goto Lb7
            goto Lb9
        Lb7:
            kotlin.Unit r10 = kotlin.Unit.a
        Lb9:
            if (r10 != r1) goto Lbc
            goto Lc7
        Lbc:
            r2 = r9
        Lbd:
            r0.j = r3
            r0.m = r4
            java.lang.Object r10 = r2.c(r0)
            if (r10 != r1) goto Lc8
        Lc7:
            return r1
        Lc8:
            return r10
        Lc9:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.StringBuilder r0 = new java.lang.StringBuilder
            java.lang.String r1 = "unexpected state: "
            r0.<init>(r1)
            r0.append(r6)
            java.lang.String r0 = r0.toString()
            java.lang.String r0 = r0.toString()
            r10.<init>(r0)
            throw r10
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.selects.e.d(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final c e(Object obj) {
        ArrayList arrayList = this.b;
        Object obj2 = null;
        if (arrayList == null) {
            return null;
        }
        Iterator it2 = arrayList.iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Object next = it2.next();
            if (((c) next).a == obj) {
                obj2 = next;
                break;
            }
        }
        c cVar = (c) obj2;
        if (cVar != null) {
            return cVar;
        }
        throw new IllegalStateException(("Clause with object " + obj + " is not found").toString());
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.jvm.functions.c, kotlin.jvm.internal.o] */
    public final void f(c cVar, boolean z) {
        AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
        if (atomicReferenceFieldUpdater.get(this) instanceof c) {
            return;
        }
        Object obj = cVar.a;
        if (!z) {
            ArrayList arrayList = this.b;
            Intrinsics.d(arrayList);
            if (!arrayList.isEmpty()) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (((c) it2.next()).a == obj) {
                        throw new IllegalStateException(B.e(obj, "Cannot use select clauses on the same object: ").toString());
                    }
                }
            }
        }
        cVar.b.invoke(obj, this, cVar.d);
        if (this.e != h.d) {
            atomicReferenceFieldUpdater.set(this, cVar);
            return;
        }
        if (!z) {
            ArrayList arrayList2 = this.b;
            Intrinsics.d(arrayList2);
            arrayList2.add(cVar);
        }
        cVar.f = this.c;
        cVar.g = this.d;
        this.c = null;
        this.d = -1;
    }

    public final int g(Object obj, Object obj2) {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = f;
            Object obj3 = atomicReferenceFieldUpdater.get(this);
            if (!(obj3 instanceof InterfaceC5026k)) {
                if (Intrinsics.b(obj3, h.b) || (obj3 instanceof c)) {
                    return 3;
                }
                if (Intrinsics.b(obj3, h.c)) {
                    return 2;
                }
                if (Intrinsics.b(obj3, h.a)) {
                    List listB = A.b(obj);
                    while (!atomicReferenceFieldUpdater.compareAndSet(this, obj3, listB)) {
                        if (atomicReferenceFieldUpdater.get(this) != obj3) {
                            break;
                        }
                    }
                    return 1;
                }
                if (!(obj3 instanceof List)) {
                    throw new IllegalStateException(("Unexpected state: " + obj3).toString());
                }
                ArrayList arrayListD0 = CollectionsKt.d0((Collection) obj3, obj);
                while (!atomicReferenceFieldUpdater.compareAndSet(this, obj3, arrayListD0)) {
                    if (atomicReferenceFieldUpdater.get(this) != obj3) {
                        break;
                    }
                }
                return 1;
            }
            c cVarE = e(obj);
            if (cVarE != null) {
                while (!atomicReferenceFieldUpdater.compareAndSet(this, obj3, cVarE)) {
                    if (atomicReferenceFieldUpdater.get(this) != obj3) {
                        break;
                    }
                }
                InterfaceC5026k interfaceC5026k = (InterfaceC5026k) obj3;
                this.e = obj2;
                C1472a c1472aK = interfaceC5026k.k(Unit.a, null);
                if (c1472aK == null) {
                    this.e = h.d;
                    return 2;
                }
                interfaceC5026k.t(c1472aK);
                return 0;
            }
            continue;
        }
    }
}
