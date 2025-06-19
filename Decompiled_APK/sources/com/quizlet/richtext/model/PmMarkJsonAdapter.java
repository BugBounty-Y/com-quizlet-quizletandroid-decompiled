package com.quizlet.richtext.model;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class PmMarkJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public PmMarkJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b(DBUserFields.Names.USER_UPGRADE_TYPE, "attrs");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, DBUserFields.Names.USER_UPGRADE_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(PmAttribute.class, m, "attr");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        PmAttribute pmAttribute = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
                if (str == null) {
                    throw b.k(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                }
            } else if (iK0 == 1) {
                pmAttribute = (PmAttribute) this.c.a(reader);
            }
        }
        reader.i();
        if (str != null) {
            return new PmMark(str, pmAttribute);
        }
        throw b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PmMark pmMark = (PmMark) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (pmMark == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        this.b.g(writer, pmMark.b);
        writer.l("attrs");
        this.c.g(writer, pmMark.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(28, "GeneratedJsonAdapter(PmMark)", "toString(...)");
    }
}
