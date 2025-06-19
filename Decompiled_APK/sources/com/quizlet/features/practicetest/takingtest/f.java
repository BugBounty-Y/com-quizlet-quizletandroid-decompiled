package com.quizlet.features.practicetest.takingtest;

import androidx.compose.runtime.InterfaceC0773a0;
import com.quizlet.features.practicetest.takingtest.data.C4407a;
import com.quizlet.features.practicetest.takingtest.data.C4413g;
import com.quizlet.search.viewmodels.A;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function0 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ f(int i, com.quizlet.report.data.a aVar, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02) {
        this.b = i;
        this.c = aVar;
        this.d = interfaceC0773a0;
        this.e = interfaceC0773a02;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                int i = this.b;
                ((Function1) this.c).invoke(Integer.valueOf(i));
                ((Function1) this.d).invoke(new C4413g(i, ((C4407a) this.e).a));
                break;
            case 1:
                ((InterfaceC0773a0) this.d).setValue(Integer.valueOf(this.b));
                ((InterfaceC0773a0) this.e).setValue(Boolean.valueOf(((com.quizlet.report.data.a) this.c).c));
                break;
            default:
                ((kotlin.jvm.functions.c) this.c).invoke(Long.valueOf(((com.quizlet.ui.models.content.carditem.f) ((com.quizlet.ui.models.search.a) this.d)).a), CollectionsKt.w0(((A) this.e).m), Integer.valueOf(this.b));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ f(Function1 function1, int i, Function1 function12, C4407a c4407a) {
        this.c = function1;
        this.b = i;
        this.d = function12;
        this.e = c4407a;
    }

    public /* synthetic */ f(kotlin.jvm.functions.c cVar, com.quizlet.ui.models.search.a aVar, A a, int i) {
        this.c = cVar;
        this.d = aVar;
        this.e = a;
        this.b = i;
    }
}
