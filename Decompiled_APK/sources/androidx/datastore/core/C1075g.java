package androidx.datastore.core;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.datastore.core.g, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1075g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public Iterator j;
    public Object k;
    public int l;
    public /* synthetic */ Object m;
    public final /* synthetic */ List n;
    public final /* synthetic */ ArrayList o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1075g(List list, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.n = list;
        this.o = arrayList;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C1075g c1075g = new C1075g(this.n, this.o, hVar);
        c1075g.m = obj;
        return c1075g;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1075g) create(obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Iterator it2;
        List list;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            obj = this.m;
            it2 = this.n.iterator();
            list = this.o;
        } else if (i == 1) {
            Object obj2 = this.k;
            Iterator it3 = this.j;
            List list2 = (List) this.m;
            androidx.glance.appwidget.protobuf.Z.e(obj);
            if (((Boolean) obj).booleanValue()) {
                list2.add(new C1074f(1, null));
                this.m = list2;
                this.j = it3;
                this.k = null;
                this.l = 2;
                throw null;
            }
            obj = obj2;
            it2 = it3;
            list = list2;
        } else {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            it2 = this.j;
            list = (List) this.m;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        if (!it2.hasNext()) {
            return obj;
        }
        if (it2.next() != null) {
            throw new ClassCastException();
        }
        this.m = list;
        this.j = it2;
        this.k = obj;
        this.l = 1;
        throw null;
    }
}
