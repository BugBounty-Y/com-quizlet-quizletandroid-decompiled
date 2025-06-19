package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.foundation.pager.C0466e;
import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.compose.runtime.C0776c;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.features.notes.detail.composables.magicnotesdetail.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4394m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0466e k;
    public final /* synthetic */ Function0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4394m(C0466e c0466e, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0466e;
        this.l = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4394m(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4394m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            InterfaceC4992i interfaceC4992iM = e0.m(e0.n(C0776c.F(new C4393l(this.k, 0)), 1));
            C0496b c0496b = new C0496b(this.l, 12);
            this.j = 1;
            if (interfaceC4992iM.b(c0496b, this) == aVar) {
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
