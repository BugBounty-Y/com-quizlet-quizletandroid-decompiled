package com.quizlet.features.universaluploadflow.pastetext;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.universaluploadflow.pastetext.data.j;
import com.quizlet.features.universaluploadflow.pastetext.data.k;
import com.quizlet.features.universaluploadflow.pastetext.data.l;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ Function0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(Function0 function0, Function0 function02, Function1 function1, Function0 function03, h hVar) {
        super(2, hVar);
        this.k = function0;
        this.l = function02;
        this.m = function1;
        this.n = function03;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        e eVar = new e(this.k, this.l, this.m, this.n, hVar);
        eVar.j = obj;
        return eVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((l) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        l lVar = (l) this.j;
        if (Intrinsics.b(lVar, com.quizlet.features.universaluploadflow.pastetext.data.h.a)) {
            this.k.invoke();
        } else if (Intrinsics.b(lVar, com.quizlet.features.universaluploadflow.pastetext.data.i.a)) {
            this.l.invoke();
        } else if (lVar instanceof k) {
            this.m.invoke(((k) lVar).a);
        } else {
            if (!(lVar instanceof j)) {
                throw new NoWhenBranchMatchedException();
            }
            this.n.invoke();
        }
        return Unit.a;
    }
}
