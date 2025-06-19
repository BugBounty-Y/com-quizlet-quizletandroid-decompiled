package androidx.paging;

import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class T extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ V l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(V v, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = v;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        T t = new T(this.l, hVar);
        t.k = obj;
        return t;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T) create((a1) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            a1 a1Var = (a1) this.k;
            V v = this.l;
            kotlin.coroutines.h hVar = null;
            J0 j0 = new J0(new P(2, null), (C1329n) v.c.c);
            C1319i operation = new C1319i(v, hVar, 1);
            Intrinsics.checkNotNullParameter(j0, "<this>");
            Intrinsics.checkNotNullParameter(operation, "operation");
            InterfaceC4992i interfaceC4992iF = AbstractC1348x.f(new com.quizlet.features.flashcards.helpers.d(new C1087t(new C1342u(j0, operation, null)), 5), new C1319i(hVar, v, 2));
            S s = new S(a1Var, 0);
            this.j = 1;
            if (interfaceC4992iF.b(s, this) == aVar) {
                return aVar;
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
