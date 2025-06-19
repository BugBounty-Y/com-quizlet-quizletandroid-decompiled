package com.quizlet.data.interactor.explanations.question.recommendations;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.repository.searchexplanations.c;
import com.quizlet.remote.model.explanations.question.recommendations.b;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(c cVar, String str, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                b bVar = (b) this.k.b;
                String str = this.l;
                this.j = 1;
                obj = bVar.a(str, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (List) obj;
        } catch (Exception unused) {
            return K.a;
        }
    }
}
