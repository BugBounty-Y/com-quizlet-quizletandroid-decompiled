package com.quizlet.login.magiclink.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ MagicLinkLogOutDialogFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(MagicLinkLogOutDialogFragment magicLinkLogOutDialogFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = magicLinkLogOutDialogFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.H(false, false);
        return Unit.a;
    }
}
