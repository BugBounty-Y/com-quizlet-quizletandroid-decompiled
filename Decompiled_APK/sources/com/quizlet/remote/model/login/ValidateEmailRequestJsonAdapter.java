package com.quizlet.remote.model.login;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ValidateEmailRequestJsonAdapter extends l {
    public final c a;
    public final l b;

    public ValidateEmailRequestJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("email");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "email");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (str = (String) this.b.a(reader)) == null) {
                throw b.k("email", "email", reader);
            }
        }
        reader.i();
        if (str != null) {
            return new ValidateEmailRequest(str);
        }
        throw b.e("email", "email", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ValidateEmailRequest validateEmailRequest = (ValidateEmailRequest) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (validateEmailRequest == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("email");
        this.b.g(writer, validateEmailRequest.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(ValidateEmailRequest)", "toString(...)");
    }
}
