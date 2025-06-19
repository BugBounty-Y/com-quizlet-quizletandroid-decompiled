package com.quizlet.infra.legacysyncengine.net;

import com.quizlet.api.model.ApiResponse;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.i;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements i, h {
    public final /* synthetic */ ModelType a;

    public /* synthetic */ e(ModelType modelType) {
        this.a = modelType;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        androidx.core.util.c cVar = (androidx.core.util.c) obj;
        ApiResponse apiResponse = (ApiResponse) cVar.a;
        if (apiResponse.hasError() && apiResponse.getError().getCode().intValue() == 409 && apiResponse.getError().getModelWrapper() != null) {
            return io.reactivex.rxjava3.core.i.o(Models.ALL_MODEL_TYPES).q(new com.google.firebase.tracing.a(19, apiResponse, cVar));
        }
        if (!apiResponse.hasError() && !apiResponse.hasValidationError()) {
            return io.reactivex.rxjava3.core.i.o(Models.ALL_MODEL_TYPES).q(new com.quizlet.infra.legacysyncengine.tasks.parse.b(cVar, 0));
        }
        return io.reactivex.rxjava3.core.i.p(new com.quizlet.infra.legacysyncengine.tasks.parse.e(this.a, (ApiResponse) cVar.a, ((Integer) cVar.b).intValue()));
    }

    @Override // io.reactivex.rxjava3.functions.i
    public boolean test(Object obj) {
        Object obj2;
        switch (((com.quizlet.quizletandroid.data.net.synchooks.a) obj).a) {
            case 0:
                obj2 = Models.IMAGE;
                break;
            default:
                obj2 = Models.TERM;
                break;
        }
        return obj2.equals(this.a);
    }
}
