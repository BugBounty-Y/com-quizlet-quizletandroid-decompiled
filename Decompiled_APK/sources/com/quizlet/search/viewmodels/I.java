package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.quizlet.data.model.User;
import com.quizlet.data.model.i2;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.data.term.TermUiModel;
import java.util.ArrayList;
import java.util.List;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ M k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        I i = new I(this.k, hVar);
        i.j = obj;
        return i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Pair pair = (Pair) this.j;
        User user = (User) pair.a;
        List<i2> list = (List) pair.b;
        M m = this.k;
        s0 s0Var = m.f;
        while (true) {
            Object value = s0Var.getValue();
            TermSearchUiModel termSearchUiModel = m.e;
            long j = termSearchUiModel.a;
            long j2 = user.a;
            int iB = AbstractC3179j6.b(user);
            com.quizlet.search.data.term.e eVar = new com.quizlet.search.data.term.e(j2, user.b, user.i, iB, user.e);
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            for (i2 i2Var : list) {
                String str = i2Var.e;
                List list2 = list;
                String str2 = i2Var.f;
                if (str2 == null) {
                    str2 = "";
                }
                arrayList.add(new TermUiModel(str, str2, i2Var.g));
                list = list2;
            }
            List list3 = list;
            if (s0Var.k(value, new com.quizlet.search.data.term.f(new com.quizlet.search.data.term.a(j, termSearchUiModel.b, termSearchUiModel.d, termSearchUiModel.e, eVar, termSearchUiModel.f, arrayList)))) {
                return Unit.a;
            }
            list = list3;
        }
    }
}
