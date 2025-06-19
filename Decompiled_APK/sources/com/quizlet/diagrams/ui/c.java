package com.quizlet.diagrams.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.composables.J;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ DiagramJSBridge j;
    public final /* synthetic */ String k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(DiagramJSBridge diagramJSBridge, String str, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = diagramJSBridge;
        this.k = str;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        J j = this.j.c;
        if (j != null) {
            j.invoke(new com.quizlet.diagrams.f(Long.parseLong(this.k), this.l));
        }
        return Unit.a;
    }
}
