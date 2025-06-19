package com.quizlet.quizletandroid.ui.library;

import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.library.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4667l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ LibraryFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4667l(LibraryFragment libraryFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = libraryFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4667l(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4667l) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            LibraryFragment libraryFragment = this.k;
            androidx.lifecycle.J viewLifecycleOwner = libraryFragment.getViewLifecycleOwner();
            Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            C4666k c4666k = new C4666k(libraryFragment, null);
            this.j = 1;
            if (p0.m(viewLifecycleOwner, b, c4666k, this) == aVar) {
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
