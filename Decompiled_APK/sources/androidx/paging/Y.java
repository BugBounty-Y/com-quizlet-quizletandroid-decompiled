package androidx.paging;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public /* synthetic */ C1350y j;
    public /* synthetic */ C1350y k;
    public final /* synthetic */ G l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public Y(G g, kotlin.coroutines.h hVar) {
        super(3, hVar);
        this.l = g;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        Y y = new Y(this.l, (kotlin.coroutines.h) obj3);
        y.j = (C1350y) obj;
        y.k = (C1350y) obj2;
        return y.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        C1350y previous = this.j;
        C1350y c1350y = this.k;
        Intrinsics.checkNotNullParameter(c1350y, "<this>");
        Intrinsics.checkNotNullParameter(previous, "previous");
        G loadType = this.l;
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        int i = c1350y.a;
        int i2 = previous.a;
        return i > i2 ? true : i < i2 ? false : AbstractC1348x.d(c1350y.b, previous.b, loadType) ? c1350y : previous;
    }
}
