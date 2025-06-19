package com.quizlet.quizletandroid.ui.common.ads;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public C4634a j;
    public int k;
    public final /* synthetic */ E l;
    public final /* synthetic */ int m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(E e, int i, String str, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.l = e;
        this.m = i;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new m(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((m) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        C4634a c4634a;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        E e = this.l;
        if (i == 0) {
            Z.e(obj);
            io.reactivex.rxjava3.core.p pVar = (io.reactivex.rxjava3.core.p) e.d.g(new C4637d(this.m, this.n));
            this.k = 1;
            obj = I1.b(pVar, this);
            if (obj != aVar) {
            }
            return aVar;
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            c4634a = this.j;
            Z.e(obj);
            Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
            return new Pair(c4634a, (Map) obj);
        }
        Z.e(obj);
        Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
        C4634a c4634a2 = (C4634a) obj;
        io.reactivex.rxjava3.core.p pVarA = e.a.a();
        this.j = c4634a2;
        this.k = 2;
        Object objB = I1.b(pVarA, this);
        if (objB != aVar) {
            c4634a = c4634a2;
            obj = objB;
            Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
            return new Pair(c4634a, (Map) obj);
        }
        return aVar;
    }
}
