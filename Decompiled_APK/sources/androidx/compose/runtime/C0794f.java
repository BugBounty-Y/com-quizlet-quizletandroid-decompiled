package androidx.compose.runtime;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* renamed from: androidx.compose.runtime.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0794f implements W {
    public final kotlin.jvm.internal.r a;
    public Throwable c;
    public final Object b = new Object();
    public ArrayList d = new ArrayList();
    public ArrayList e = new ArrayList();
    public final androidx.compose.runtime.internal.a f = new androidx.compose.runtime.internal.a(0);

    /* JADX WARN: Multi-variable type inference failed */
    public C0794f(Function0 function0) {
        this.a = (kotlin.jvm.internal.r) function0;
    }

    /* JADX WARN: Type inference failed for: r10v3, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    @Override // androidx.compose.runtime.W
    public final Object P(Function1 function1, kotlin.coroutines.h frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        C0792e c0792e = new C0792e(function1, c5028l);
        synchronized (this.b) {
            Throwable th = this.c;
            if (th != null) {
                kotlin.p pVar = kotlin.r.b;
                c5028l.resumeWith(androidx.glance.appwidget.protobuf.Z.b(th));
            } else {
                boolean zIsEmpty = this.d.isEmpty();
                this.d.add(c0792e);
                if (zIsEmpty) {
                    this.f.set(1);
                }
                c5028l.u(new androidx.compose.foundation.text.selection.n0(11, this, c0792e));
                if (zIsEmpty) {
                    try {
                        this.a.invoke();
                    } catch (Throwable th2) {
                        synchronized (this.b) {
                            try {
                                if (this.c == null) {
                                    this.c = th2;
                                    ArrayList arrayList = this.d;
                                    int size = arrayList.size();
                                    for (int i = 0; i < size; i++) {
                                        C5028l c5028l2 = ((C0792e) arrayList.get(i)).b;
                                        kotlin.p pVar2 = kotlin.r.b;
                                        c5028l2.resumeWith(androidx.glance.appwidget.protobuf.Z.b(th2));
                                    }
                                    this.d.clear();
                                    this.f.set(0);
                                    Unit unit = Unit.a;
                                }
                            } catch (Throwable th3) {
                                throw th3;
                            }
                        }
                    }
                }
            }
        }
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    public final void b(long j) {
        Object objB;
        synchronized (this.b) {
            try {
                ArrayList arrayList = this.d;
                this.d = this.e;
                this.e = arrayList;
                this.f.set(0);
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    C0792e c0792e = (C0792e) arrayList.get(i);
                    c0792e.getClass();
                    try {
                        kotlin.p pVar = kotlin.r.b;
                        objB = c0792e.a.invoke(Long.valueOf(j));
                    } catch (Throwable th) {
                        kotlin.p pVar2 = kotlin.r.b;
                        objB = androidx.glance.appwidget.protobuf.Z.b(th);
                    }
                    c0792e.b.resumeWith(objB);
                }
                arrayList.clear();
                Unit unit = Unit.a;
            } catch (Throwable th2) {
                throw th2;
            }
        }
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final Object fold(Object obj, Function2 operation) {
        Intrinsics.checkNotNullParameter(operation, "operation");
        return operation.invoke(obj, this);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext.Element get(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.a(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext minusKey(kotlin.coroutines.l lVar) {
        return kotlin.coroutines.k.b(this, lVar);
    }

    @Override // kotlin.coroutines.CoroutineContext
    public final CoroutineContext plus(CoroutineContext coroutineContext) {
        return kotlin.coroutines.k.c(coroutineContext, this);
    }
}
