package com.quizlet.login.common.interactors;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.api.IQuizletApiClient;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ com.quizlet.data.interactor.progress.c l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v(String str, com.quizlet.data.interactor.progress.c cVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.interactor.progress.c cVar = this.l;
        try {
            if (i == 0) {
                Z.e(obj);
                Map request = V.f(new Pair("googleToken", this.k), new Pair("state", ((com.quizlet.qutils.string.c) cVar.b).b()));
                io.ktor.client.plugins.api.d dVar = (io.ktor.client.plugins.api.d) cVar.a;
                Intrinsics.checkNotNullParameter(request, "request");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((IQuizletApiClient) dVar.b).a(request).g(new com.quizlet.login.authentication.login.a(dVar, 0));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                this.j = 1;
                obj = I1.b(gVarG, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (com.quizlet.login.authentication.data.i) obj;
        } catch (Exception e) {
            return ((io.ktor.client.plugins.api.d) cVar.a).x(null, e);
        }
    }
}
