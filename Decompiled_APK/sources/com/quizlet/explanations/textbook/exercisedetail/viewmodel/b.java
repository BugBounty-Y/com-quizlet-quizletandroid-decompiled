package com.quizlet.explanations.textbook.exercisedetail.viewmodel;

import com.quizlet.explanations.textbook.exercisedetail.data.d;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ c b;

    public /* synthetic */ b(c cVar, int i) {
        this.a = i;
        this.b = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(list, "list");
                Boolean bool = (Boolean) list.get(0);
                d dVar = (d) list.get(1);
                Intrinsics.d(bool);
                boolean zBooleanValue = bool.booleanValue();
                Intrinsics.d(dVar);
                this.b.getClass();
                if (!zBooleanValue) {
                    break;
                } else {
                    break;
                }
            default:
                List list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                Boolean bool2 = (Boolean) list2.get(0);
                d dVar2 = (d) list2.get(1);
                Intrinsics.d(bool2);
                boolean zBooleanValue2 = bool2.booleanValue();
                Intrinsics.d(dVar2);
                this.b.getClass();
                if (!zBooleanValue2) {
                    break;
                } else {
                    break;
                }
        }
        return K.a;
    }
}
