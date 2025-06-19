package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.K5;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ s j;
    public final /* synthetic */ x k;
    public final /* synthetic */ Function0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(s sVar, x xVar, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = sVar;
        this.k = xVar;
        this.l = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        s sVar = this.j;
        if (K5.a(sVar)) {
            this.k.a();
            this.l.invoke();
            ((L0) sVar.c).setValue(u.b);
        }
        return Unit.a;
    }
}
