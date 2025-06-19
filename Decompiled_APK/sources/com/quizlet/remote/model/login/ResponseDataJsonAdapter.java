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
public final class ResponseDataJsonAdapter extends l {
    public final c a;
    public final l b;

    public ResponseDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("data");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(EmailData.class, M.a, "contents");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        EmailData emailData = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (emailData = (EmailData) this.b.a(reader)) == null) {
                throw b.k("contents", "data", reader);
            }
        }
        reader.i();
        if (emailData != null) {
            return new ResponseData(emailData);
        }
        throw b.e("contents", "data", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ResponseData responseData = (ResponseData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (responseData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("data");
        this.b.g(writer, responseData.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(ResponseData)", "toString(...)");
    }
}
