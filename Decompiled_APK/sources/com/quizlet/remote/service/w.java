package com.quizlet.remote.service;

import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
import kotlin.Metadata;
import kotlin.Unit;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public interface w {
    @retrofit2.http.o("report")
    Object a(@retrofit2.http.t(DBImageRefFields.Names.MODEL_TYPE) int i, @retrofit2.http.t("reason") int i2, @retrofit2.http.t(DBImageRefFields.Names.MODEL_ID) String str, @NotNull kotlin.coroutines.h<? super Unit> hVar);
}
