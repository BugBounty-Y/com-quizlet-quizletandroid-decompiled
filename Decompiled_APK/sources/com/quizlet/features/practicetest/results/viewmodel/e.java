package com.quizlet.features.practicetest.results.viewmodel;

import com.facebook.login.B;
import com.quizlet.features.practicetest.results.data.i;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.p;
import kotlin.r;

/* loaded from: classes3.dex */
public final class e implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        i iVar = i.a;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                ((h) obj).C(iVar);
                break;
            case 1:
                ((h) obj).C(iVar);
                break;
            default:
                p pVar = r.b;
                ((kotlin.coroutines.p) obj).resumeWith(B.b.a());
                break;
        }
        return Unit.a;
    }
}
