package com.quizlet.quizletandroid.ui.startpage.nav2;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4726p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ OldHomeFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4726p(OldHomeFragment oldHomeFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = oldHomeFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4726p(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4726p) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        String str = OldHomeFragment.d1;
        this.j.Y();
        return Unit.a;
    }
}
