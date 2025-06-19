package com.quizlet.remote.model.login;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
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
public final class UsernameCheckJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public UsernameCheckJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("success", "suggestions");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Boolean.TYPE, m, "success");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, String.class), m, "suggestions");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw b.k("success", "success", reader);
                }
            } else if (iK0 == 1) {
                list = (List) this.c.a(reader);
            }
        }
        reader.i();
        if (bool != null) {
            return new UsernameCheck(bool.booleanValue(), list);
        }
        throw b.e("success", "success", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        UsernameCheck usernameCheck = (UsernameCheck) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (usernameCheck == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("success");
        this.b.g(writer, Boolean.valueOf(usernameCheck.a));
        writer.l("suggestions");
        this.c.g(writer, usernameCheck.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(35, "GeneratedJsonAdapter(UsernameCheck)", "toString(...)");
    }
}
