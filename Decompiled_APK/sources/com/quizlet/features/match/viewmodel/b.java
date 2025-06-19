package com.quizlet.features.match.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.O6;
import com.google.android.gms.internal.mlkit_vision_barcode.P6;
import com.quizlet.features.match.data.AbstractC4355k;
import com.quizlet.features.match.data.C4350f;
import com.quizlet.features.match.data.C4351g;
import com.quizlet.studiablemodels.MixedOptionMatchingStudiableQuestion;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ AbstractC4355k l;
    public final /* synthetic */ AbstractC4355k m;
    public final /* synthetic */ O6 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, AbstractC4355k abstractC4355k, AbstractC4355k abstractC4355k2, O6 o6, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = abstractC4355k;
        this.m = abstractC4355k2;
        this.n = o6;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object c4351g;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        AbstractC4355k cardItem = this.m;
        AbstractC4355k cardItem2 = this.l;
        com.quizlet.features.match.studyengine.g gVar = cVar.c;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            com.quizlet.features.match.studyengine.e eVar = (com.quizlet.features.match.studyengine.e) gVar;
            eVar.b();
            ArrayList arrayList = eVar.b;
            obj = eVar.a(arrayList.indexOf(cardItem2), arrayList.indexOf(cardItem), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        Boolean bool = (Boolean) obj;
        boolean zBooleanValue = bool.booleanValue();
        com.quizlet.features.match.studyengine.e eVar2 = (com.quizlet.features.match.studyengine.e) gVar;
        eVar2.getClass();
        Intrinsics.checkNotNullParameter(cardItem2, "cardItem");
        ArrayList arrayList2 = eVar2.b;
        int iIndexOf = arrayList2.indexOf(cardItem2);
        Intrinsics.checkNotNullParameter(cardItem, "cardItem");
        int iIndexOf2 = arrayList2.indexOf(cardItem);
        eVar2.b();
        MixedOptionMatchingStudiableQuestion mixedOptionMatchingStudiableQuestion = eVar2.d;
        if (mixedOptionMatchingStudiableQuestion == null) {
            Intrinsics.m("currentQuestion");
            throw null;
        }
        com.quizlet.features.match.logging.c cVar2 = new com.quizlet.features.match.logging.c(mixedOptionMatchingStudiableQuestion, iIndexOf, Integer.valueOf(iIndexOf2));
        String str = cVar.j[iIndexOf];
        Intrinsics.checkNotNullExpressionValue(str, "get(...)");
        P6.c(cVar.d, cVar2, str, "answer", bool, null, 48);
        O6 o6 = this.n;
        if (zBooleanValue) {
            com.quizlet.features.match.studyengine.e eVar3 = (com.quizlet.features.match.studyengine.e) gVar;
            eVar3.b();
            com.quizlet.features.match.studyengine.b bVar = eVar3.a;
            if (bVar.c.size() == bVar.d) {
                cVar.f.l(Unit.a);
            }
            c4351g = new C4350f(o6);
        } else {
            c4351g = new C4351g(o6);
        }
        cVar.h.l(c4351g);
        cVar.J();
        return Unit.a;
    }
}
