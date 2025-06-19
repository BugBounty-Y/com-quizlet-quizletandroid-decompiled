package com.quizlet.features.practicetest.takingtest;

import com.quizlet.features.practicetest.takingtest.data.C4413g;
import com.quizlet.features.practicetest.takingtest.data.C4414h;
import com.quizlet.features.practicetest.takingtest.data.C4420n;
import com.quizlet.features.practicetest.takingtest.data.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Function1 c;

    public /* synthetic */ b(Function1 function1, Function1 function12, int i) {
        this.a = i;
        this.b = function1;
        this.c = function12;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                C4413g it2 = (C4413g) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                this.b.invoke(Boolean.TRUE);
                this.c.invoke(new C4420n(it2));
                break;
            case 1:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                this.b.invoke(Boolean.valueOf(it3.length() > 0));
                this.c.invoke(new x(new C4414h(it3)));
                break;
            default:
                Intrinsics.checkNotNullParameter(obj, "<this>");
                Function1 function1 = this.b;
                if (function1 != null) {
                    function1.invoke(obj);
                }
                this.c.invoke(obj);
                break;
        }
        return Unit.a;
    }
}
