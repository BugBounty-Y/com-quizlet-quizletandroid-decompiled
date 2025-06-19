package com.quizlet.remote.model.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.repository.folderwithcreator.e;
import com.quizlet.generated.enums.P;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import io.reactivex.rxjava3.core.p;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ P l;
    public final /* synthetic */ Long m;
    public final /* synthetic */ long n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(e eVar, P p, Long l, long j, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = p;
        this.m = l;
        this.n = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            p<ApiThreeWrapper<MeteringInfoResponse>> pVarA = ((com.quizlet.remote.service.p) eVar.b).a(this.l.a(), this.m);
            this.j = 1;
            obj = I1.b(pVarA, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
        MeteringInfoResponse meteringInfoResponse = (MeteringInfoResponse) apiThreeWrapper.a();
        if (meteringInfoResponse != null) {
            Object obj2 = eVar.c;
            return com.quizlet.quizletandroid.ui.profile.p.g(meteringInfoResponse.d, meteringInfoResponse.e, this.l, this.m, this.n);
        }
        ApiError apiError = apiThreeWrapper.b;
        if (apiError == null || (str = apiError.a) == null) {
            str = "An exception occurred while trying to fetch remote MeteringInfo";
        }
        throw new IllegalArgumentException(str);
    }
}
