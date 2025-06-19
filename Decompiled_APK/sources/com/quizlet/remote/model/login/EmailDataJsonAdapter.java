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
public final class EmailDataJsonAdapter extends l {
    public final c a;
    public final l b;

    public EmailDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("validateEmail");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(ValidateEmail.class, M.a, "contents");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        ValidateEmail validateEmail = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (validateEmail = (ValidateEmail) this.b.a(reader)) == null) {
                throw b.k("contents", "validateEmail", reader);
            }
        }
        reader.i();
        if (validateEmail != null) {
            return new EmailData(validateEmail);
        }
        throw b.e("contents", "validateEmail", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        EmailData emailData = (EmailData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (emailData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("validateEmail");
        this.b.g(writer, emailData.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(31, "GeneratedJsonAdapter(EmailData)", "toString(...)");
    }
}
