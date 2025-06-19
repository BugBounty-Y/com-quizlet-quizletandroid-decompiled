package com.quizlet.search.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.search.composables.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4794m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ String j;
    public final /* synthetic */ InterfaceC0773a0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4794m(String str, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = str;
        this.k = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4794m(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4794m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.setValue(this.j);
        return Unit.a;
    }
}
