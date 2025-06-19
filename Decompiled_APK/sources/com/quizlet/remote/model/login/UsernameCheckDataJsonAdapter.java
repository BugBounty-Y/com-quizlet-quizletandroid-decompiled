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
public final class UsernameCheckDataJsonAdapter extends l {
    public final c a;
    public final l b;

    public UsernameCheckDataJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("checkUsername");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(UsernameCheck.class, M.a, "checkUsername");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        UsernameCheck usernameCheck = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (usernameCheck = (UsernameCheck) this.b.a(reader)) == null) {
                throw b.k("checkUsername", "checkUsername", reader);
            }
        }
        reader.i();
        if (usernameCheck != null) {
            return new UsernameCheckData(usernameCheck);
        }
        throw b.e("checkUsername", "checkUsername", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UsernameCheckData usernameCheckData = (UsernameCheckData) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (usernameCheckData == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("checkUsername");
        this.b.g(writer, usernameCheckData.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(UsernameCheckData)", "toString(...)");
    }
}
