package com.quizlet.login.common.interactors;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.login.common.interactors.data.A;
import com.quizlet.login.common.interactors.data.B;
import com.quizlet.quizletandroid.R;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class p extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.work.impl.model.e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public p(androidx.work.impl.model.e eVar, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new p(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((p) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        ServerProvidedError error;
        List responses;
        ApiResponse apiResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String str = this.l;
        androidx.work.impl.model.e eVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                io.reactivex.rxjava3.internal.operators.single.g gVarW = ((IQuizletApiClient) eVar.b).w(str);
                this.j = 1;
                obj = I1.b(gVarW, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) ((K) obj).b;
            if (apiThreeWrapper == null || (error = apiThreeWrapper.getError()) == null) {
                error = (apiThreeWrapper == null || (responses = apiThreeWrapper.getResponses()) == null || (apiResponse = (ApiResponse) CollectionsKt.firstOrNull(responses)) == null) ? null : apiResponse.getError();
            }
            if (error == null) {
                return new B(str);
            }
            eVar.getClass();
            Integer numB = ApiErrorResolver.b(error.getIdentifier());
            int iIntValue = numB != null ? numB.intValue() : R.string.unable_to_reach_quizlet_msg;
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new A(new com.quizlet.qutils.string.f(iIntValue, C4933y.P(args)));
        } catch (Exception unused) {
            Object[] args2 = new Object[0];
            Intrinsics.checkNotNullParameter(args2, "args");
            return new A(new com.quizlet.qutils.string.f(R.string.unable_to_reach_quizlet_msg, C4933y.P(args2)));
        }
    }
}
