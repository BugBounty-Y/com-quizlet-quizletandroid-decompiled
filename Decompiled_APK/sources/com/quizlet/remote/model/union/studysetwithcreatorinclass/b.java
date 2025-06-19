package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import androidx.glance.appwidget.protobuf.Z;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ List l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, List list, boolean z, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = list;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
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
        List list = this.l;
        e eVar = this.k;
        a aVar2 = new a(eVar, list, this.m, null);
        this.j = 1;
        eVar.getClass();
        Object objJ = E.J(eVar.d, new d(eVar, aVar2, null), this);
        return objJ == aVar ? aVar : objJ;
    }
}
