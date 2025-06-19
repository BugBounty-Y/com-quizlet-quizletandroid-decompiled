package com.quizlet.remote.model.base;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public class ApiResponse {
    public PagingInfo a;
    public List b;
    public ModelError c;

    @InterfaceC4853h(name = "error")
    public static /* synthetic */ void getError$annotations() {
    }

    @InterfaceC4853h(name = "paging")
    public static /* synthetic */ void getPagingInfo$annotations() {
    }

    @InterfaceC4853h(name = "validationErrors")
    public static /* synthetic */ void getValidationErrors$annotations() {
    }
}
