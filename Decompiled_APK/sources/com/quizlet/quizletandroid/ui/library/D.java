package com.quizlet.quizletandroid.ui.library;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3674m5;
import com.quizlet.quizletandroid.ui.library.data.C4647a;
import com.quizlet.quizletandroid.ui.library.data.C4648b;
import com.quizlet.quizletandroid.ui.library.data.C4650d;
import com.quizlet.quizletandroid.ui.library.data.C4651e;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ c0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(c0 c0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.k, hVar);
        d.j = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((List) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        AbstractC3674m5 c4650d;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        List<com.quizlet.data.model.C> list = (List) this.j;
        if (list.isEmpty()) {
            c4650d = C4651e.a;
        } else {
            Intrinsics.checkNotNullParameter(list, "<this>");
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
            for (com.quizlet.data.model.C c : list) {
                long j = c.a;
                String str = c.b;
                C4647a c4647a = new C4647a(c.c, j, str);
                Intrinsics.checkNotNullParameter(c, "<this>");
                arrayList.add(new C4648b(c4647a, new com.quizlet.ui.models.content.listitem.a(c.a, str)));
            }
            c4650d = new C4650d(AbstractC3409x1.k(arrayList));
        }
        s0 s0Var = this.k.t;
        do {
            value = s0Var.getValue();
        } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.library.data.J.a((com.quizlet.quizletandroid.ui.library.data.J) value, null, null, null, null, c4650d, false, false, false, 239)));
        return Unit.a;
    }
}
