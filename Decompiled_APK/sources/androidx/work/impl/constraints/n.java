package androidx.work.impl.constraints;

import androidx.compose.foundation.text.C0494i0;
import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.q;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ m k;
    public final /* synthetic */ q l;
    public final /* synthetic */ j m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(m mVar, q qVar, j jVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = mVar;
        this.l = qVar;
        this.m = jVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            q spec = this.l;
            m mVar = this.k;
            mVar.getClass();
            Intrinsics.checkNotNullParameter(spec, "spec");
            ArrayList arrayList = new ArrayList();
            Iterator it2 = mVar.a.iterator();
            while (it2.hasNext()) {
                Object next = it2.next();
                if (((androidx.work.impl.constraints.controllers.e) next).b(spec)) {
                    arrayList.add(next);
                }
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it3 = arrayList.iterator();
            while (it3.hasNext()) {
                arrayList2.add(((androidx.work.impl.constraints.controllers.e) it3.next()).a(spec.j));
            }
            InterfaceC4992i interfaceC4992iM = e0.m(new C1087t((InterfaceC4992i[]) CollectionsKt.w0(arrayList2).toArray(new InterfaceC4992i[0]), 2));
            C0494i0 c0494i0 = new C0494i0(9, this.m, spec);
            this.j = 1;
            if (interfaceC4992iM.b(c0494i0, this) == aVar) {
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
