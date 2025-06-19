package com.quizlet.search.data.blended;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(com.quizlet.data.repository.folderwithcreatorinclass.e eVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        com.google.firebase.crashlytics.internal.common.j jVar = (com.google.firebase.crashlytics.internal.common.j) this.k.a;
        this.j = 1;
        io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) jVar.b;
        Object objJ = E.J((AbstractC5040y) dVar.d, new com.quizlet.remote.model.search.a(dVar, this.l, null), this);
        return objJ == aVar ? aVar : objJ;
    }
}
