package com.quizlet.remote.model.search;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.C1;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.search.SearchTypeAheadResultResponse;
import com.quizlet.remote.service.y;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.google.android.gms.internal.appset.e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.google.android.gms.internal.appset.e eVar, String str, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        SearchTypeAheadResultResponse searchTypeAheadResultResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.google.android.gms.internal.appset.e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            y yVar = (y) eVar.b;
            this.j = 1;
            obj = yVar.a(this.l, this);
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
        com.quizlet.remote.model.explanations.search.c cVar = (com.quizlet.remote.model.explanations.search.c) eVar.c;
        Intrinsics.checkNotNullParameter(response, "response");
        String strA = Q.a(response.a.f);
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        if (apiThreeWrapper != null && (searchTypeAheadResultResponse = (SearchTypeAheadResultResponse) apiThreeWrapper.a()) != null) {
            List remotes = searchTypeAheadResultResponse.d.a.b;
            Intrinsics.checkNotNullParameter(remotes, "remotes");
            return new C1(strA, S.f(cVar, remotes));
        }
        return new C1();
    }
}
