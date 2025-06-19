package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ApiResponseJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;

    public ApiResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        PagingInfo pagingInfo = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                pagingInfo = (PagingInfo) this.b.a(reader);
                z = true;
            } else if (iK0 == 1) {
                list = (List) this.c.a(reader);
                z2 = true;
            } else if (iK0 == 2) {
                modelError = (ModelError) this.d.a(reader);
                z3 = true;
            }
        }
        reader.i();
        ApiResponse apiResponse = new ApiResponse();
        if (z) {
            apiResponse.a = pagingInfo;
        }
        if (z2) {
            apiResponse.b = list;
        }
        if (z3) {
            apiResponse.c = modelError;
        }
        return apiResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiResponse apiResponse = (ApiResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("paging");
        this.b.g(writer, apiResponse.a);
        writer.l("validationErrors");
        this.c.g(writer, apiResponse.b);
        writer.l("error");
        this.d.g(writer, apiResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(ApiResponse)", "toString(...)");
    }
}
