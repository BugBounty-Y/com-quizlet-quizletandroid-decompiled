package com.quizlet.remote.model.metering;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.C4179x0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.repository.folderwithcreator.e;
import com.quizlet.remote.model.base.ApiError;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.p;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ InterfaceC4176w0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(e eVar, InterfaceC4176w0 interfaceC4176w0, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = interfaceC4176w0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        String str;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        InterfaceC4176w0 interfaceC4176w0 = this.l;
        if (i == 0) {
            Z.e(obj);
            p pVar = (p) eVar.b;
            int iA = interfaceC4176w0.c0().a();
            Long lR = interfaceC4176w0.r();
            C4179x0 c4179x0 = interfaceC4176w0 instanceof C4179x0 ? (C4179x0) interfaceC4176w0 : null;
            io.reactivex.rxjava3.core.p<ApiThreeWrapper<MeteringInfoResponse>> pVarB = pVar.b(iA, lR, c4179x0 != null ? new Integer(c4179x0.a) : null);
            this.j = 1;
            obj = I1.b(pVarB, this);
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
            return com.quizlet.quizletandroid.ui.profile.p.g(meteringInfoResponse.d, meteringInfoResponse.e, interfaceC4176w0.c0(), interfaceC4176w0.r(), interfaceC4176w0.i());
        }
        ApiError apiError = apiThreeWrapper.b;
        if (apiError == null || (str = apiError.a) == null) {
            str = "An exception occurred while trying to save MeteringInfo to remote";
        }
        throw new IllegalArgumentException(str);
    }
}
