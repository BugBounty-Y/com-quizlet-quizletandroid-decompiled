package com.quizlet.api.util;

import com.quizlet.api.error.ApiErrorException;
import com.quizlet.api.error.ModelErrorException;
import com.quizlet.api.error.ValidationErrorException;
import com.quizlet.api.model.ApiError;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.model.ValidationError;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.flowable.b;
import java.util.List;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements h {
    public static final a b = new a(0);
    public static final a c = new a(1);
    public static final a d = new a(2);
    public static final a e = new a(3);
    public static final a f = new a(4);
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        ValidationError validationError;
        switch (this.a) {
            case 0:
                ApiThreeWrapper it2 = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ApiError error = it2.getError();
                if (error != null) {
                    return p.d(new ApiErrorException(error));
                }
                b bVarF = p.f(it2);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
            case 1:
                ApiThreeWrapper it3 = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return it3.getResponses();
            case 2:
                List list = (List) obj;
                Intrinsics.d(list);
                ApiResponse apiResponse = (ApiResponse) CollectionsKt.firstOrNull(list);
                if (apiResponse != null) {
                    return p.f(apiResponse);
                }
                b bVarD = p.d(new IllegalStateException("no data in response"));
                Intrinsics.checkNotNullExpressionValue(bVarD, "error(...)");
                return bVarD;
            case 3:
                ApiResponse it4 = (ApiResponse) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                List<ValidationError> validationErrors = it4.getValidationErrors();
                if (validationErrors != null && (validationError = (ValidationError) CollectionsKt.firstOrNull(validationErrors)) != null) {
                    return p.d(new ValidationErrorException(validationError));
                }
                b bVarF2 = p.f(it4);
                Intrinsics.checkNotNullExpressionValue(bVarF2, "just(...)");
                return bVarF2;
            default:
                ApiResponse it5 = (ApiResponse) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                ModelError error2 = it5.getError();
                if (error2 != null) {
                    return p.d(new ModelErrorException(error2));
                }
                b bVarF3 = p.f(it5);
                Intrinsics.checkNotNullExpressionValue(bVarF3, "just(...)");
                return bVarF3;
        }
    }
}
