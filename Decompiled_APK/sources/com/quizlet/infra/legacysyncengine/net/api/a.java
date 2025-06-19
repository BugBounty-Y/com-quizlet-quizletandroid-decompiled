package com.quizlet.infra.legacysyncengine.net.api;

import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.util.ApiThreeWrapperUtil;
import com.quizlet.db.data.models.persisted.DBStudySet;
import io.reactivex.rxjava3.functions.h;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        switch (this.a) {
            case 0:
                K response = (K) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                return ApiThreeWrapperUtil.a((ApiThreeWrapper) response.b);
            default:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                Object obj2 = pair.a;
                Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
                return (DBStudySet) obj2;
        }
    }
}
