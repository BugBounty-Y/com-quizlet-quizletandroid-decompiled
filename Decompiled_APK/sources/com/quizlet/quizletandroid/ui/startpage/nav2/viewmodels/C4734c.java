package com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4710f;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4734c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C4739h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4734c(C4739h c4739h, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c4739h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4734c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4734c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C4710f c4710f = C4710f.a;
            this.j = 1;
            if (C4739h.A(this.k, c4710f, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
