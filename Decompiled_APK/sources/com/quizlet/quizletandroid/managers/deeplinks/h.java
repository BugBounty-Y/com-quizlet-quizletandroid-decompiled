package com.quizlet.quizletandroid.managers.deeplinks;

import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ModelWrapper;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.quizletandroid.util.links.NoMatchingQuizletClassFoundException;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class h implements io.reactivex.rxjava3.functions.h {
    public static final h a = new h();

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        ModelWrapper modelWrapper;
        List<DBGroup> groups;
        List responses;
        K response = (K) obj;
        Intrinsics.checkNotNullParameter(response, "response");
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) response.b;
        DBGroup dBGroup = null;
        ApiResponse apiResponse = (apiThreeWrapper == null || (responses = apiThreeWrapper.getResponses()) == null) ? null : (ApiResponse) CollectionsKt.firstOrNull(responses);
        if (apiResponse != null && (modelWrapper = apiResponse.getModelWrapper()) != null && (groups = modelWrapper.getGroups()) != null) {
            dBGroup = (DBGroup) CollectionsKt.firstOrNull(groups);
        }
        return dBGroup == null ? io.reactivex.rxjava3.core.p.d(new NoMatchingQuizletClassFoundException()) : io.reactivex.rxjava3.core.p.f(Long.valueOf(dBGroup.getId()));
    }
}
