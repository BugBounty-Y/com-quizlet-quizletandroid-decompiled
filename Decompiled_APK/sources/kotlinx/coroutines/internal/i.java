package kotlinx.coroutines.internal;

import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public class i {
    public static final /* synthetic */ AtomicReferenceFieldUpdater a = AtomicReferenceFieldUpdater.newUpdater(i.class, Object.class, "_next$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater b = AtomicReferenceFieldUpdater.newUpdater(i.class, Object.class, "_prev$volatile");
    public static final /* synthetic */ AtomicReferenceFieldUpdater c = AtomicReferenceFieldUpdater.newUpdater(i.class, Object.class, "_removedRef$volatile");
    private volatile /* synthetic */ Object _next$volatile = this;
    private volatile /* synthetic */ Object _prev$volatile = this;
    private volatile /* synthetic */ Object _removedRef$volatile;

    public final boolean d(i iVar, int i) {
        while (true) {
            i iVarE = e();
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
            if (iVarE == null) {
                Object obj = atomicReferenceFieldUpdater.get(this);
                while (true) {
                    iVarE = (i) obj;
                    if (!iVarE.h()) {
                        break;
                    }
                    obj = atomicReferenceFieldUpdater.get(iVarE);
                }
            }
            if (iVarE instanceof h) {
                return (((h) iVarE).d & i) == 0 && iVarE.d(iVar, i);
            }
            atomicReferenceFieldUpdater.set(iVar, iVarE);
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater2 = a;
            atomicReferenceFieldUpdater2.set(iVar, this);
            while (!atomicReferenceFieldUpdater2.compareAndSet(iVarE, this, iVar)) {
                if (atomicReferenceFieldUpdater2.get(iVarE) != this) {
                    break;
                }
            }
            iVar.f(this);
            return true;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x0031, code lost:
    
        r6 = ((kotlinx.coroutines.internal.n) r6).a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x0039, code lost:
    
        if (r5.compareAndSet(r4, r3, r6) == false) goto L24;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x0041, code lost:
    
        if (r5.get(r4) == r3) goto L43;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final kotlinx.coroutines.internal.i e() {
        /*
            r9 = this;
        L0:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r0 = kotlinx.coroutines.internal.i.b
            java.lang.Object r1 = r0.get(r9)
            kotlinx.coroutines.internal.i r1 = (kotlinx.coroutines.internal.i) r1
            r2 = 0
            r3 = r1
        La:
            r4 = r2
        Lb:
            java.util.concurrent.atomic.AtomicReferenceFieldUpdater r5 = kotlinx.coroutines.internal.i.a
            java.lang.Object r6 = r5.get(r3)
            if (r6 != r9) goto L24
            if (r1 != r3) goto L16
            return r3
        L16:
            boolean r2 = r0.compareAndSet(r9, r1, r3)
            if (r2 == 0) goto L1d
            return r3
        L1d:
            java.lang.Object r2 = r0.get(r9)
            if (r2 == r1) goto L16
            goto L0
        L24:
            boolean r7 = r9.h()
            if (r7 == 0) goto L2b
            return r2
        L2b:
            boolean r7 = r6 instanceof kotlinx.coroutines.internal.n
            if (r7 == 0) goto L4b
            if (r4 == 0) goto L44
            kotlinx.coroutines.internal.n r6 = (kotlinx.coroutines.internal.n) r6
            kotlinx.coroutines.internal.i r6 = r6.a
        L35:
            boolean r7 = r5.compareAndSet(r4, r3, r6)
            if (r7 == 0) goto L3d
            r3 = r4
            goto La
        L3d:
            java.lang.Object r7 = r5.get(r4)
            if (r7 == r3) goto L35
            goto L0
        L44:
            java.lang.Object r3 = r0.get(r3)
            kotlinx.coroutines.internal.i r3 = (kotlinx.coroutines.internal.i) r3
            goto Lb
        L4b:
            java.lang.String r4 = "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode"
            kotlin.jvm.internal.Intrinsics.e(r6, r4)
            r4 = r6
            kotlinx.coroutines.internal.i r4 = (kotlinx.coroutines.internal.i) r4
            r8 = r4
            r4 = r3
            r3 = r8
            goto Lb
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.internal.i.e():kotlinx.coroutines.internal.i");
    }

    public final void f(i iVar) {
        while (true) {
            AtomicReferenceFieldUpdater atomicReferenceFieldUpdater = b;
            i iVar2 = (i) atomicReferenceFieldUpdater.get(iVar);
            if (a.get(this) != iVar) {
                return;
            }
            while (!atomicReferenceFieldUpdater.compareAndSet(iVar, iVar2, this)) {
                if (atomicReferenceFieldUpdater.get(iVar) != iVar2) {
                    break;
                }
            }
            if (h()) {
                iVar.e();
                return;
            }
            return;
        }
    }

    public final i g() {
        i iVar;
        Object obj = a.get(this);
        n nVar = obj instanceof n ? (n) obj : null;
        if (nVar != null && (iVar = nVar.a) != null) {
            return iVar;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type kotlinx.coroutines.internal.LockFreeLinkedListNode");
        return (i) obj;
    }

    public boolean h() {
        return a.get(this) instanceof n;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        int i = 5;
        sb.append(new androidx.compose.foundation.lazy.i(1, i, E.class, this, "classSimpleName", "getClassSimpleName(Ljava/lang/Object;)Ljava/lang/String;"));
        sb.append('@');
        sb.append(E.r(this));
        return sb.toString();
    }
}
