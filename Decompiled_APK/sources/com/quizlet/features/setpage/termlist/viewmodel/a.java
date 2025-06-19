package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.setpage.termlist.data.m;
import com.quizlet.features.setpage.termlist.data.n;
import java.io.Serializable;
import java.util.List;
import java.util.Set;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.e {
    public /* synthetic */ List j;
    public /* synthetic */ com.quizlet.features.setpage.termlist.data.a k;
    public /* synthetic */ Set l;
    public /* synthetic */ m m;
    public final /* synthetic */ j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(j jVar, kotlin.coroutines.h hVar) {
        super(5, hVar);
        this.n = jVar;
    }

    @Override // kotlin.jvm.functions.e
    public final Object c(Object obj, Object obj2, Object obj3, Object obj4, Serializable serializable) {
        a aVar = new a(this.n, (kotlin.coroutines.h) serializable);
        aVar.j = (List) obj;
        aVar.k = (com.quizlet.features.setpage.termlist.data.a) obj2;
        aVar.l = (Set) obj3;
        aVar.m = (m) obj4;
        return aVar.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        List list = this.j;
        com.quizlet.features.setpage.termlist.data.a aVar2 = this.k;
        Set set = this.l;
        m mVar = this.m;
        j jVar = this.n;
        jVar.j.l(list);
        return new n(j.A(jVar, mVar), aVar2, set, mVar, jVar.f.d(jVar.g));
    }
}
