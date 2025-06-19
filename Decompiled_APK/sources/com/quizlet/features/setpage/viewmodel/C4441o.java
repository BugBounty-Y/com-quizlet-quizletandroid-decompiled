package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.viewmodel.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4441o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;
    public final /* synthetic */ Function0 l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C4441o(P p, Function0 function0, Function1 function1, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
        this.l = function0;
        this.m = (kotlin.coroutines.jvm.internal.i) function1;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4441o(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4441o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function1] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        ?? r2 = this.m;
        P p = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                io.reactivex.rxjava3.subjects.d dVar = ((com.quizlet.remote.connectivity.b) p.q).a.a;
                this.j = 1;
                obj = I1.c(dVar, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            Intrinsics.checkNotNullExpressionValue(obj, "awaitFirst(...)");
            if (((com.quizlet.data.connectivity.b) obj).a) {
                p.H(new C4439m(r2, null));
            } else {
                this.l.invoke();
            }
        } catch (Exception unused) {
            p.H(new C4440n(r2, null));
        }
        return Unit.a;
    }
}
