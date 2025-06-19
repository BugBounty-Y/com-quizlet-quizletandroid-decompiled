package coil3.intercept;

import androidx.glance.appwidget.protobuf.Z;
import coil3.request.m;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ J l;
    public final /* synthetic */ J m;
    public final /* synthetic */ coil3.request.g n;
    public final /* synthetic */ Object o;
    public final /* synthetic */ J p;
    public final /* synthetic */ coil3.f q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(h hVar, J j, J j2, coil3.request.g gVar, Object obj, J j3, coil3.f fVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = j;
        this.m = j2;
        this.n = gVar;
        this.o = obj;
        this.p = j3;
        this.q = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        coil3.fetch.i iVar = (coil3.fetch.i) this.l.a;
        coil3.d dVar = (coil3.d) this.m.a;
        m mVar = (m) this.p.a;
        this.j = 1;
        Object objA = h.a(this.k, iVar, dVar, this.n, this.o, mVar, this.q, this);
        return objA == aVar ? aVar : objA;
    }
}
