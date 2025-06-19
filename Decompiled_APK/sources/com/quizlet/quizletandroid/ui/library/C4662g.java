package com.quizlet.quizletandroid.ui.library;

import com.quizlet.quizletandroid.ui.library.data.C4648b;
import com.quizlet.quizletandroid.ui.library.data.C4649c;
import com.quizlet.quizletandroid.ui.library.data.C4656j;
import com.quizlet.quizletandroid.ui.library.data.C4657k;
import com.quizlet.quizletandroid.ui.library.data.C4658l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* renamed from: com.quizlet.quizletandroid.ui.library.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4662g implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Function1 d;

    public /* synthetic */ C4662g(int i, Object obj, Function1 function1, int i2) {
        this.a = i2;
        this.b = i;
        this.c = obj;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.d.invoke(new com.quizlet.quizletandroid.ui.library.data.o(this.b, (C4648b) this.c));
                break;
            case 1:
                this.d.invoke(new C4658l(this.b, (C4649c) this.c));
                break;
            case 2:
                this.d.invoke(new com.quizlet.quizletandroid.ui.library.data.n(this.b, (com.quizlet.library.viewmodels.e) this.c));
                break;
            case 3:
                this.d.invoke(new C4656j(this.b, (com.quizlet.library.viewmodels.a) this.c));
                break;
            default:
                this.d.invoke(new C4657k(this.b, (com.quizlet.quizletandroid.ui.library.data.K) this.c));
                break;
        }
        return Unit.a;
    }
}
