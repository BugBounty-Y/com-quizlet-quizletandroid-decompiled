package com.quizlet.features.universaluploadflow.pastetext.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.s2;
import com.quizlet.features.universaluploadflow.pastetext.data.k;
import com.quizlet.generated.enums.EnumC4483g0;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(String str, d dVar, h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String str = this.k;
        d dVar = this.l;
        if (i == 0) {
            Z.e(obj);
            s2 s2Var = new s2(str, !dVar.g);
            this.j = 1;
            obj = dVar.b.q(dVar.f, s2Var, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.universaluploadflow.logging.b.e(dVar.c, null, dVar.g, new Integer(str.length()), null, EnumC4483g0.TEXT.a(), 9);
        dVar.e.h(new k((String) obj));
        return Unit.a;
    }
}
