package androidx.compose.ui.platform;

import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class U extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ V l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U(V v, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        U u = new U(this.l, hVar);
        u.k = obj;
        return u;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((U) create((C0974w0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0974w0 c0974w0 = (C0974w0) this.k;
            this.k = c0974w0;
            V v = this.l;
            this.j = 1;
            C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(this));
            c5028l.r();
            androidx.compose.ui.text.input.B b = v.b;
            androidx.compose.ui.text.input.u uVar = b.a;
            uVar.a();
            b.b.set(new androidx.compose.ui.text.input.H(b, uVar));
            c5028l.u(new androidx.compose.foundation.text.selection.n0(22, c0974w0, v));
            Object objQ = c5028l.q();
            if (objQ == aVar) {
                Intrinsics.checkNotNullParameter(this, "frame");
            }
            if (objQ == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}
