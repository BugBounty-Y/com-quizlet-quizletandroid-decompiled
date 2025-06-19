package com.quizlet.remote.model.explanations.search;

import androidx.work.impl.model.v;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.A1;
import com.quizlet.data.model.C4107a0;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.explanations.search.ExplanationsSearchResultResponse;
import io.reactivex.rxjava3.functions.h;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.r;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a implements h {
    public final /* synthetic */ v a;

    public a(v vVar) {
        this.a = vVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        List listF;
        ExplanationsSearchResultResponse explanationsSearchResultResponse;
        PagingInfo pagingInfo;
        ExplanationsSearchResultResponse explanationsSearchResultResponse2;
        ExplanationsSearchResultResponse.Models models;
        List remotes;
        K response = (K) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        v vVar = this.a;
        if (apiThreeWrapper == null || (explanationsSearchResultResponse2 = (ExplanationsSearchResultResponse) apiThreeWrapper.a()) == null || (models = explanationsSearchResultResponse2.d) == null || (remotes = models.a) == null) {
            listF = kotlin.collections.K.a;
        } else {
            com.quizlet.quizletandroid.ui.login.h hVar = (com.quizlet.quizletandroid.ui.login.h) vVar.c;
            Intrinsics.checkNotNullParameter(remotes, "remotes");
            listF = S.f(hVar, remotes);
        }
        ApiThreeWrapper apiThreeWrapper2 = (ApiThreeWrapper) response.b;
        A1 a1I = (apiThreeWrapper2 == null || (explanationsSearchResultResponse = (ExplanationsSearchResultResponse) apiThreeWrapper2.a()) == null || (pagingInfo = explanationsSearchResultResponse.a) == null) ? null : com.quizlet.quizletandroid.ui.folder.logging.a.i(pagingInfo);
        r rVar = response.a.f;
        Intrinsics.checkNotNullExpressionValue(rVar, "headers(...)");
        return new C4107a0(listF, a1I, Q.a(rVar));
    }
}
