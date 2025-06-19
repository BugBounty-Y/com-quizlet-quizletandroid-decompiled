package com.quizlet.remote.model.search;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.quizlet.data.model.C4183y1;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.y;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ io.ktor.client.plugins.api.d k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(io.ktor.client.plugins.api.d dVar, String str, h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        SearchAllResultsResponse searchAllResultsResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        io.ktor.client.plugins.api.d dVar = this.k;
        if (i == 0) {
            Z.e(obj);
            y yVar = (y) dVar.b;
            this.j = 1;
            obj = yVar.b(this.l, 1, 1, 1, false, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        K response = (K) obj;
        com.quizlet.data.repository.user.a aVar2 = (com.quizlet.data.repository.user.a) dVar.c;
        Intrinsics.checkNotNullParameter(response, "response");
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        return (apiThreeWrapper == null || (searchAllResultsResponse = (SearchAllResultsResponse) apiThreeWrapper.a()) == null) ? C4183y1.c : new C4183y1(aVar2.c(searchAllResultsResponse), Q.a(response.a.f));
    }
}
