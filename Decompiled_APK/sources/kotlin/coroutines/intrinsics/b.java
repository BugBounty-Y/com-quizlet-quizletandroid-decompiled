package kotlin.coroutines.intrinsics;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.search.composables.E;
import io.ktor.utils.io.u;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.g {
    public int j;
    public final /* synthetic */ E k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(u uVar, E e) {
        super(uVar);
        this.k = e;
        Intrinsics.e(uVar, "null cannot be cast to non-null type kotlin.coroutines.Continuation<kotlin.Any?>");
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("This coroutine had already completed");
            }
            this.j = 2;
            Z.e(obj);
            return obj;
        }
        this.j = 1;
        Z.e(obj);
        E e = this.k;
        O.d(1, e);
        return e.invoke(this);
    }
}
