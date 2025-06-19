package com.quizlet.infra.legacysyncengine.models.serializers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.quizlet.data.model.C4115c0;
import com.quizlet.db.data.models.base.DBModel;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.internal.operators.completable.m;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import timber.log.c;

/* loaded from: classes3.dex */
public class ApiThreeRequestSerializer {
    protected static final String DATA_STRING = "data";
    protected static final String TAG = "ApiThreeRequestSerializer";
    protected final ObjectWriter mObjectWriter;

    public ApiThreeRequestSerializer(ObjectWriter objectWriter) {
        this.mObjectWriter = objectWriter;
        if (objectWriter.getConfig().isEnabled(MapperFeature.REQUIRE_SETTERS_FOR_GETTERS)) {
            return;
        }
        c.a(new IllegalStateException("ObjectReader must require setters for getters"));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static /* synthetic */ ArrayList lambda$requestFilesForModels$0(ArrayList arrayList, List list) throws Throwable {
        arrayList.addAll(list);
        return arrayList;
    }

    public String requestBodyForModel(DBModel dBModel) {
        return requestBodyForModels(Collections.singletonList(dBModel));
    }

    public String requestBodyForModels(List<? extends DBModel> list) {
        try {
            HashMap map = new HashMap();
            map.put(DATA_STRING, list);
            return this.mObjectWriter.writeValueAsString(map);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    public List<C4115c0> requestFilesForModel(DBModel dBModel) {
        return dBModel.getFilesForRequest();
    }

    public List<C4115c0> requestFilesForModels(List<? extends DBModel> list) {
        return (List) new m(i.o(list).q(new com.google.android.material.search.a(this, 27)), new ArrayList(), new a(0)).b();
    }
}
