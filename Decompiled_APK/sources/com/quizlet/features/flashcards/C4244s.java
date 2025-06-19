package com.quizlet.features.flashcards;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.flashcards.s, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4244s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.lifecycle.J k;
    public final /* synthetic */ S l;
    public final /* synthetic */ com.quizlet.features.flashcards.autoplay.o m;
    public final /* synthetic */ Context n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4244s(Context context, androidx.lifecycle.J j, S s, com.quizlet.features.flashcards.autoplay.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = s;
        this.m = oVar;
        this.n = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4244s(this.n, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4244s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            S s = this.l;
            com.quizlet.features.flashcards.autoplay.o oVar = this.m;
            Context context = this.n;
            androidx.lifecycle.J j = this.k;
            r rVar = new r(context, j, s, oVar, null);
            this.j = 1;
            if (p0.m(j, b, rVar, this) == aVar) {
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
