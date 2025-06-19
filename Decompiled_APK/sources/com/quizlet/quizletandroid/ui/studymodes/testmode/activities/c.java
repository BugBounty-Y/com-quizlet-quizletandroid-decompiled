package com.quizlet.quizletandroid.ui.studymodes.testmode.activities;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.learnpaywall.l;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ TestStudyModeActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(TestStudyModeActivity testStudyModeActivity, h hVar) {
        super(2, hVar);
        this.k = testStudyModeActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.k, hVar);
        cVar.j = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((l) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        l lVar = (l) this.j;
        boolean z = lVar.a;
        String str = TestStudyModeActivity.v;
        this.k.d0(z, lVar.b);
        return Unit.a;
    }
}
