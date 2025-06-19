package okio.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.jvm.functions.Function2;
import okio.t;
import okio.x;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ t m;
    public final /* synthetic */ x n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(t tVar, x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = tVar;
        this.n = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        d dVar = new d(this.m, this.n, hVar);
        dVar.l = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((kotlin.sequences.i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            kotlin.sequences.i iVar = (kotlin.sequences.i) this.l;
            C4927s c4927s = new C4927s();
            this.k = 1;
            if (b.c(iVar, this.m, c4927s, this.n, true, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
