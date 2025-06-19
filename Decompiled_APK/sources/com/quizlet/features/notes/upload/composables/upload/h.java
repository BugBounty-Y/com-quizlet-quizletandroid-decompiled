package com.quizlet.features.notes.upload.composables.upload;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function1 l;
    public final /* synthetic */ Function0 m;
    public final /* synthetic */ Function0 n;
    public final /* synthetic */ Function0 o;
    public final /* synthetic */ kotlin.jvm.functions.d p;
    public final /* synthetic */ kotlin.jvm.functions.c q;
    public final /* synthetic */ Function2 r;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(Function0 function0, Function1 function1, Function0 function02, Function0 function03, Function0 function04, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function1;
        this.m = function02;
        this.n = function03;
        this.o = function04;
        this.p = dVar;
        this.q = cVar;
        this.r = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.k, this.l, this.m, this.n, this.o, this.p, this.q, this.r, hVar);
        hVar2.j = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((com.quizlet.features.notes.upload.events.i) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.upload.events.i iVar = (com.quizlet.features.notes.upload.events.i) this.j;
        if (Intrinsics.b(iVar, com.quizlet.features.notes.upload.events.a.a)) {
            this.k.invoke();
        } else if (iVar instanceof com.quizlet.features.notes.upload.events.b) {
            this.l.invoke(((com.quizlet.features.notes.upload.events.b) iVar).a);
        } else if (Intrinsics.b(iVar, com.quizlet.features.notes.upload.events.h.a)) {
            this.m.invoke();
        } else if (Intrinsics.b(iVar, com.quizlet.features.notes.upload.events.e.a)) {
            this.n.invoke();
        } else if (iVar instanceof com.quizlet.features.notes.upload.events.f) {
            this.o.invoke();
        } else if (iVar instanceof com.quizlet.features.notes.upload.events.d) {
            com.quizlet.features.notes.upload.events.d dVar = (com.quizlet.features.notes.upload.events.d) iVar;
            this.p.invoke(Boolean.valueOf(dVar.a), dVar.b, dVar.c, dVar.d);
        } else if (iVar instanceof com.quizlet.features.notes.upload.events.c) {
            com.quizlet.features.notes.upload.events.c cVar = (com.quizlet.features.notes.upload.events.c) iVar;
            this.q.invoke(cVar.a, Boolean.valueOf(cVar.b), cVar.c);
        } else if (iVar instanceof com.quizlet.features.notes.upload.events.g) {
            com.quizlet.features.notes.upload.events.g gVar = (com.quizlet.features.notes.upload.events.g) iVar;
            this.r.invoke(new Long(gVar.a), gVar.b);
        }
        return Unit.a;
    }
}
