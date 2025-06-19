package com.quizlet.data.repository.searchexplanations;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.Y;
import com.quizlet.remote.service.l;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ String l;
    public final /* synthetic */ Integer m;
    public final /* synthetic */ String n;
    public final /* synthetic */ Integer o;
    public final /* synthetic */ List p;
    public final /* synthetic */ boolean q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, String str, Integer num, String str2, Integer num2, List list, boolean z, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = str;
        this.m = num;
        this.n = str2;
        this.o = num2;
        this.p = list;
        this.q = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
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
        v vVar = (v) this.k.b;
        String query = this.l;
        Intrinsics.checkNotNullParameter(query, "query");
        List filters = this.p;
        Intrinsics.checkNotNullParameter(filters, "filters");
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) vVar.b;
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(filters, "filters");
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(filters, 10));
        Iterator it2 = filters.iterator();
        while (it2.hasNext()) {
            arrayList.add(((Y) it2.next()).b());
        }
        g gVarG = ((l) cVar.b).a(query, this.m, this.n, this.o, arrayList, this.q).g(new com.quizlet.remote.model.explanations.search.a(vVar));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        this.j = 1;
        Object objB = I1.b(gVarG, this);
        return objB == aVar ? aVar : objB;
    }
}
