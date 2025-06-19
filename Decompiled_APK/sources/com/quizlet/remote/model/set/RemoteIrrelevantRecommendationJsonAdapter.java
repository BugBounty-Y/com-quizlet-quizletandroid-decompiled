package com.quizlet.remote.model.set;

import com.google.android.gms.measurement.internal.Z;
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
public final class RemoteIrrelevantRecommendationJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;

    public RemoteIrrelevantRecommendationJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "personId", DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_TYPE, "created");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "personId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, DBImageRefFields.Names.MODEL_TYPE);
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Integer num = null;
        Long l4 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 != 0) {
                    l lVar2 = this.c;
                    if (iK0 == 1) {
                        l = (Long) lVar2.a(reader);
                        if (l == null) {
                            throw com.squareup.moshi.internal.b.k("personId", "personId", reader);
                        }
                    } else if (iK0 == 2) {
                        l2 = (Long) lVar2.a(reader);
                        if (l2 == null) {
                            throw com.squareup.moshi.internal.b.k(DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_ID, reader);
                        }
                    } else if (iK0 == 3) {
                        num = (Integer) this.d.a(reader);
                        if (num == null) {
                            throw com.squareup.moshi.internal.b.k(DBImageRefFields.Names.MODEL_TYPE, DBImageRefFields.Names.MODEL_TYPE, reader);
                        }
                    } else if (iK0 == 4) {
                        l4 = (Long) lVar.a(reader);
                    }
                } else {
                    l3 = (Long) lVar.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        Long l5 = l2;
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("personId", "personId", reader);
        }
        long jLongValue = l.longValue();
        if (l5 == null) {
            throw com.squareup.moshi.internal.b.e(DBImageRefFields.Names.MODEL_ID, DBImageRefFields.Names.MODEL_ID, reader);
        }
        long jLongValue2 = l5.longValue();
        if (num != null) {
            return new RemoteIrrelevantRecommendation(l3, jLongValue, jLongValue2, num.intValue(), l4);
        }
        throw com.squareup.moshi.internal.b.e(DBImageRefFields.Names.MODEL_TYPE, DBImageRefFields.Names.MODEL_TYPE, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteIrrelevantRecommendation remoteIrrelevantRecommendation = (RemoteIrrelevantRecommendation) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteIrrelevantRecommendation == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        l lVar = this.b;
        lVar.g(writer, remoteIrrelevantRecommendation.a);
        writer.l("personId");
        Long lValueOf = Long.valueOf(remoteIrrelevantRecommendation.b);
        l lVar2 = this.c;
        lVar2.g(writer, lValueOf);
        writer.l(DBImageRefFields.Names.MODEL_ID);
        Z.k(remoteIrrelevantRecommendation.c, lVar2, writer, DBImageRefFields.Names.MODEL_TYPE);
        this.d.g(writer, Integer.valueOf(remoteIrrelevantRecommendation.d));
        writer.l("created");
        lVar.g(writer, remoteIrrelevantRecommendation.e);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(52, "GeneratedJsonAdapter(RemoteIrrelevantRecommendation)", "toString(...)");
    }
}
