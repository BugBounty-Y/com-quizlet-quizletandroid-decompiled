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
public final class ApiErrorJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public ApiErrorJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("message", "identifier", "code");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "serverMessage");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.class, m, "code");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        Integer num = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("serverMessage", "message", reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("identifier", "identifier", reader);
                    }
                } else if (iK0 == 2) {
                    num = (Integer) this.c.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("serverMessage", "message", reader);
        }
        if (str2 != null) {
            return new ApiError(str, str2, num);
        }
        throw com.squareup.moshi.internal.b.e("identifier", "identifier", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ApiError apiError = (ApiError) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (apiError == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("message");
        l lVar = this.b;
        lVar.g(writer, apiError.a);
        writer.l("identifier");
        lVar.g(writer, apiError.b);
        writer.l("code");
        this.c.g(writer, apiError.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(30, "GeneratedJsonAdapter(ApiError)", "toString(...)");
    }
}
