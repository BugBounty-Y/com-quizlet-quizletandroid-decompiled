package com.quizlet.features.flashcards;

import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.features.flashcards.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4232f implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ S b;

    public /* synthetic */ C4232f(S s, int i) {
        this.a = i;
        this.b = s;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                String string = (String) obj;
                Intrinsics.checkNotNullParameter(string, "text");
                com.quizlet.features.infra.models.flashcards.a type = com.quizlet.features.infra.models.flashcards.a.a;
                S s = this.b;
                Intrinsics.checkNotNullParameter(type, "type");
                Intrinsics.checkNotNullParameter(string, "text");
                if (!StringsKt.O(string)) {
                    d0 d0Var = s.r;
                    Intrinsics.checkNotNullParameter(string, "string");
                    com.quizlet.qutils.string.e eVar = new com.quizlet.qutils.string.e(string);
                    Object[] args = new Object[0];
                    Intrinsics.checkNotNullParameter(args, "args");
                    d0Var.h(new com.quizlet.features.flashcards.data.i(eVar, new com.quizlet.qutils.string.f(R.string.empty, C4933y.P(args))));
                }
                return Unit.a;
            default:
                com.quizlet.features.flashcards.autoplay.e eVar2 = (com.quizlet.features.flashcards.autoplay.e) obj;
                boolean zB = Intrinsics.b(eVar2, com.quizlet.features.flashcards.autoplay.d.a);
                S s2 = this.b;
                if (zB) {
                    s2.t.l(com.quizlet.features.flashcards.data.o.a(s2.G(), 0, 0, 0, 0, false, false, true, false, null, null, 959));
                } else if (Intrinsics.b(eVar2, com.quizlet.features.flashcards.autoplay.d.c)) {
                    s2.t.l(com.quizlet.features.flashcards.data.o.a(s2.G(), 0, 0, 0, 0, false, false, false, false, null, null, 959));
                } else if (eVar2 instanceof com.quizlet.features.flashcards.autoplay.c) {
                    s2.K(false);
                } else {
                    if (!Intrinsics.b(eVar2, com.quizlet.features.flashcards.autoplay.d.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    s2.v.h(com.quizlet.ui.compose.M.a);
                }
                return Unit.a;
        }
    }
}
