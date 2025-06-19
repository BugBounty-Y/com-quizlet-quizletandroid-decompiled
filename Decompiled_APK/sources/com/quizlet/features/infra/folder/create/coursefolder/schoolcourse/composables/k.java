package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ boolean j;
    public final /* synthetic */ androidx.compose.ui.focus.p k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(boolean z, androidx.compose.ui.focus.p pVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = z;
        this.k = pVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new k(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.j) {
            this.k.b();
        }
        return Unit.a;
    }
}
