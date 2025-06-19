package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.InterfaceC5025j0;

/* loaded from: classes.dex */
public final class g0 implements H {
    public final /* synthetic */ A a;
    public final /* synthetic */ kotlin.jvm.internal.J b;
    public final /* synthetic */ kotlinx.coroutines.C c;
    public final /* synthetic */ A d;
    public final /* synthetic */ C5028l e;
    public final /* synthetic */ kotlinx.coroutines.sync.c f;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i g;

    /* JADX WARN: Multi-variable type inference failed */
    public g0(A a, kotlin.jvm.internal.J j, kotlinx.coroutines.C c, A a2, C5028l c5028l, kotlinx.coroutines.sync.c cVar, Function2 function2) {
        this.a = a;
        this.b = j;
        this.c = c;
        this.d = a2;
        this.e = c5028l;
        this.f = cVar;
        this.g = (kotlin.coroutines.jvm.internal.i) function2;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // androidx.lifecycle.H
    public final void d(J j, A event) {
        Intrinsics.checkNotNullParameter(j, "<unused var>");
        Intrinsics.checkNotNullParameter(event, "event");
        kotlin.jvm.internal.J j2 = this.b;
        if (event == this.a) {
            j2.a = kotlinx.coroutines.E.A(this.c, null, null, new f0(this.f, this.g, null), 3);
            return;
        }
        if (event == this.d) {
            InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) j2.a;
            if (interfaceC5025j0 != null) {
                interfaceC5025j0.j(null);
            }
            j2.a = null;
        }
        if (event == A.ON_DESTROY) {
            kotlin.p pVar = kotlin.r.b;
            this.e.resumeWith(Unit.a);
        }
    }
}
