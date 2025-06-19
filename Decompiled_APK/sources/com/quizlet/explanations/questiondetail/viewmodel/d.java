package com.quizlet.explanations.questiondetail.viewmodel;

import androidx.compose.foundation.text.z0;
import androidx.compose.ui.platform.C0960p;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;
    public final /* synthetic */ String l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, String str, boolean z, h hVar) {
        super(2, hVar);
        this.k = fVar;
        this.l = str;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        f fVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.repository.searchexplanations.c cVar = fVar.e;
            this.j = 1;
            cVar.getClass();
            obj = E.J((AbstractC5040y) cVar.c, new com.quizlet.data.interactor.explanations.question.recommendations.a(cVar, this.l, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        kotlinx.collections.immutable.b bVarI = AbstractC3409x1.i((Iterable) obj);
        fVar.s.j(new com.quizlet.explanations.questiondetail.data.e(bVarI, new C0960p(2, this.k, f.class, "onTextbookClick", "onTextbookClick(Lcom/quizlet/data/model/Textbook;I)V", 0, 4), this.m, new z0(1, this.k, f.class, "onSearchClick", "onSearchClick(Ljava/lang/String;)V", 0, 29)));
        return Unit.a;
    }
}
