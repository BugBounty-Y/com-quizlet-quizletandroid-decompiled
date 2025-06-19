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
public final class ValidationErrorJsonAdapter extends l {
    public final c a;
    public final l b;

    public ValidationErrorJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("message", "identifier", "field");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "serverMessage");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
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
                } else if (iK0 == 2 && (str3 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("field_", "field", reader);
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
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("identifier", "identifier", reader);
        }
        if (str3 != null) {
            return new ValidationError(str, str2, str3);
        }
        throw com.squareup.moshi.internal.b.e("field_", "field", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ValidationError validationError = (ValidationError) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (validationError == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("message");
        l lVar = this.b;
        lVar.g(writer, validationError.a);
        writer.l("identifier");
        lVar.g(writer, validationError.b);
        writer.l("field");
        lVar.g(writer, validationError.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(ValidationError)", "toString(...)");
    }
}
