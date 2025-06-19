package com.quizlet.quizletandroid.ui.library;

import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.d0;

/* renamed from: com.quizlet.quizletandroid.ui.library.k, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4666k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ LibraryFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4666k(LibraryFragment libraryFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = libraryFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4666k(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((C4666k) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            throw new KotlinNothingValueException();
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        LibraryFragment libraryFragment = this.k;
        d0 d0Var = ((c0) ((InterfaceC4646d) libraryFragment.k.getValue())).u;
        androidx.paging.S s = new androidx.paging.S(libraryFragment, 2);
        this.j = 1;
        d0Var.getClass();
        d0.m(d0Var, s, this);
        return aVar;
    }
}
