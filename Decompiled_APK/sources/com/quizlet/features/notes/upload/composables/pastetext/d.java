package com.quizlet.features.notes.upload.composables.pastetext;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.notes.upload.events.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ kotlin.jvm.functions.c k;
    public final /* synthetic */ Function2 l;
    public final /* synthetic */ Function0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(kotlin.jvm.functions.c cVar, Function2 function2, Function0 function0, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = function2;
        this.m = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, this.l, this.m, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.notes.upload.events.i) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.upload.events.i iVar = (com.quizlet.features.notes.upload.events.i) this.j;
        if (iVar instanceof com.quizlet.features.notes.upload.events.c) {
            com.quizlet.features.notes.upload.events.c cVar = (com.quizlet.features.notes.upload.events.c) iVar;
            this.k.invoke(cVar.a, Boolean.valueOf(cVar.b), cVar.c);
        } else if (iVar instanceof g) {
            g gVar = (g) iVar;
            this.l.invoke(new Long(gVar.a), gVar.b);
        } else if (Intrinsics.b(iVar, com.quizlet.features.notes.upload.events.a.a)) {
            this.m.invoke();
        }
        return Unit.a;
    }
}
