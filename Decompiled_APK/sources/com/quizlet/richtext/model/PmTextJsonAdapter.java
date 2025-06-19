package com.quizlet.richtext.model;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class PmTextJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public PmTextJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b(DBUserFields.Names.USER_UPGRADE_TYPE, "text", "marks");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, DBUserFields.Names.USER_UPGRADE_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, PmMark.class), m, "marks");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw b.k(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw b.k("text", "text", reader);
                    }
                } else if (iK0 == 2) {
                    list = (List) this.c.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
        }
        if (str2 != null) {
            return new PmText(str, str2, list);
        }
        throw b.e("text", "text", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PmText pmText = (PmText) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (pmText == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        String str = pmText.c;
        l lVar = this.b;
        lVar.g(writer, str);
        writer.l("text");
        lVar.g(writer, pmText.d);
        writer.l("marks");
        this.c.g(writer, pmText.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(28, "GeneratedJsonAdapter(PmText)", "toString(...)");
    }
}
