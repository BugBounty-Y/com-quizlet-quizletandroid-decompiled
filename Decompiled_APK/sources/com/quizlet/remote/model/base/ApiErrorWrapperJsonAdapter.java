package com.quizlet.remote.model.base;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ApiErrorWrapperJsonAdapter extends l {
    public final c a;
    public final l b;

    public ApiErrorWrapperJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(ApiError.class, M.a, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        ApiError apiError = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                apiError = (ApiError) this.b.a(reader);
            }
        }
        reader.i();
        return new ApiErrorWrapper(apiError);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiErrorWrapper apiErrorWrapper = (ApiErrorWrapper) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiErrorWrapper == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("error");
        this.b.g(writer, apiErrorWrapper.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(ApiErrorWrapper)", "toString(...)");
    }
}
