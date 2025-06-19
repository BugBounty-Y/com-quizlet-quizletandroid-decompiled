package com.quizlet.remote.model.set;

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
public final class RemoteRecommendedStudiableJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteRecommendedStudiableJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "rank", "studiableId", "studiableType");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "rank");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Integer num = null;
        Integer num2 = null;
        Integer num3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 != 0) {
                l lVar = this.c;
                if (iK0 == 1) {
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("rank", "rank", reader);
                    }
                } else if (iK0 == 2) {
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("studiableId", "studiableId", reader);
                    }
                } else if (iK0 == 3 && (num3 = (Integer) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("studiableType", "studiableType", reader);
                }
            } else {
                l = (Long) this.b.a(reader);
            }
        }
        reader.i();
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("rank", "rank", reader);
        }
        int iIntValue = num.intValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e("studiableId", "studiableId", reader);
        }
        int iIntValue2 = num2.intValue();
        if (num3 != null) {
            return new RemoteRecommendedStudiable(l, iIntValue, iIntValue2, num3.intValue());
        }
        throw com.squareup.moshi.internal.b.e("studiableType", "studiableType", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteRecommendedStudiable remoteRecommendedStudiable = (RemoteRecommendedStudiable) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteRecommendedStudiable == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, remoteRecommendedStudiable.a);
        writer.l("rank");
        Integer numValueOf = Integer.valueOf(remoteRecommendedStudiable.b);
        l lVar = this.c;
        lVar.g(writer, numValueOf);
        writer.l("studiableId");
        AbstractC4178x.p(remoteRecommendedStudiable.c, lVar, writer, "studiableType");
        lVar.g(writer, Integer.valueOf(remoteRecommendedStudiable.d));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(RemoteRecommendedStudiable)", "toString(...)");
    }
}
