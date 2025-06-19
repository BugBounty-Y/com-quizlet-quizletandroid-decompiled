package com.quizlet.quizletandroid.ui.classcreation;

import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.S;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ ClassCreationActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(ClassCreationActivity classCreationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = classCreationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((a) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            Z.e(obj);
            throw new KotlinNothingValueException();
        }
        Z.e(obj);
        ClassCreationActivity classCreationActivity = this.k;
        d0 d0Var = ((i) classCreationActivity.i.getValue()).e;
        S s = new S(classCreationActivity, 1);
        this.j = 1;
        d0Var.getClass();
        d0.m(d0Var, s, this);
        return aVar;
    }
}
