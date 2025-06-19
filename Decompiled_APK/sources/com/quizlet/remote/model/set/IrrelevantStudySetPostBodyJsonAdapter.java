package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBImageRefFields;
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
public final class IrrelevantStudySetPostBodyJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public IrrelevantStudySetPostBodyJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("personId", DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_TYPE, "created");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "personId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "created");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        Integer num3 = null;
        Long l = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                    }
                } else if (iK0 == 1) {
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k(DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_ID, reader);
                    }
                } else if (iK0 == 2) {
                    num3 = (Integer) lVar.a(reader);
                    if (num3 == null) {
                        throw com.squareup.moshi.internal.b.k(DBImageRefFields.Names.MODEL_TYPE, DBImageRefFields.Names.MODEL_TYPE, reader);
                    }
                } else if (iK0 == 3 && (l = (Long) this.c.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("created", "created", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Integer num4 = num;
        if (num4 == null) {
            throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
        }
        int iIntValue = num4.intValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e(DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_ID, reader);
        }
        int iIntValue2 = num2.intValue();
        if (num3 == null) {
            throw com.squareup.moshi.internal.b.e(DBImageRefFields.Names.MODEL_TYPE, DBImageRefFields.Names.MODEL_TYPE, reader);
        }
        int iIntValue3 = num3.intValue();
        if (l != null) {
            return new IrrelevantStudySetPostBody(l.longValue(), iIntValue, iIntValue2, iIntValue3);
        }
        throw com.squareup.moshi.internal.b.e("created", "created", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        IrrelevantStudySetPostBody irrelevantStudySetPostBody = (IrrelevantStudySetPostBody) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (irrelevantStudySetPostBody == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("personId");
        Integer numValueOf = Integer.valueOf(irrelevantStudySetPostBody.a);
        l lVar = this.b;
        lVar.g(writer, numValueOf);
        writer.l(DBImageRefFields.Names.MODEL_ID);
        AbstractC4178x.p(irrelevantStudySetPostBody.b, lVar, writer, DBImageRefFields.Names.MODEL_TYPE);
        AbstractC4178x.p(irrelevantStudySetPostBody.c, lVar, writer, "created");
        this.c.g(writer, Long.valueOf(irrelevantStudySetPostBody.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(IrrelevantStudySetPostBody)", "toString(...)");
    }
}
