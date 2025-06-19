package androidx.glance.appwidget;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class T extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Set k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T(Set set, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = set;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        T t = new T(this.k, hVar);
        t.j = obj;
        return t;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        Set set = (Set) bVar.c(X.g);
        if (set != null) {
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : set) {
                if (!this.k.contains((String) obj2)) {
                    arrayList.add(obj2);
                }
            }
            if (!arrayList.isEmpty()) {
                androidx.datastore.preferences.core.b bVarG = bVar.g();
                bVarG.e(X.g, kotlin.collections.b0.e(set, arrayList));
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    bVarG.d(P.a(X.d, (String) it2.next()));
                }
                return bVarG.h();
            }
        }
        return bVar;
    }
}
