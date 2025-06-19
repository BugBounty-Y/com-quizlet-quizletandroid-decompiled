package kotlinx.coroutines.flow;

import com.android.billingclient.api.C1472a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.internal.AbstractC4993a;

/* loaded from: classes3.dex */
public final class P extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ InterfaceC4992i l;
    public final /* synthetic */ AbstractC4993a m;
    public final /* synthetic */ Object n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public P(InterfaceC4992i interfaceC4992i, W w, Object obj, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = interfaceC4992i;
        this.m = (AbstractC4993a) w;
        this.n = obj;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.internal.a] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        P p = new P(this.l, this.m, this.n, hVar);
        p.k = obj;
        return p;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((P) create((g0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v1, types: [kotlinx.coroutines.flow.W, kotlinx.coroutines.flow.internal.a, kotlinx.coroutines.flow.j] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            int iOrdinal = ((g0) this.k).ordinal();
            ?? r1 = this.m;
            if (iOrdinal == 0) {
                this.j = 1;
                if (this.l.b(r1, this) == aVar) {
                    return aVar;
                }
            } else if (iOrdinal != 1) {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                C1472a c1472a = e0.a;
                Object obj2 = this.n;
                if (obj2 == c1472a) {
                    r1.g();
                } else {
                    r1.h(obj2);
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
