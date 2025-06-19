package com.quizlet.remote.model.notes;

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
public final class StudyNotesRequestJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public StudyNotesRequestJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("private");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(Boolean.TYPE, M.a, "isPrivate");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (bool = (Boolean) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("isPrivate", "private", reader);
            }
        }
        reader.i();
        if (bool != null) {
            return new StudyNotesRequest(bool.booleanValue());
        }
        throw com.squareup.moshi.internal.b.e("isPrivate", "private", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudyNotesRequest studyNotesRequest = (StudyNotesRequest) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studyNotesRequest == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("private");
        this.b.g(writer, Boolean.valueOf(studyNotesRequest.a));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(StudyNotesRequest)", "toString(...)");
    }
}
