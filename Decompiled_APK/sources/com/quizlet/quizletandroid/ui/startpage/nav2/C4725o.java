package com.quizlet.quizletandroid.ui.startpage.nav2;

import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4725o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ OldHomeFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4725o(OldHomeFragment oldHomeFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = oldHomeFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4725o(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4725o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            OldHomeFragment oldHomeFragment = this.k;
            androidx.lifecycle.J viewLifecycleOwner = oldHomeFragment.getViewLifecycleOwner();
            Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            C4724n c4724n = new C4724n(oldHomeFragment, null);
            this.j = 1;
            if (p0.m(viewLifecycleOwner, b, c4724n, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
