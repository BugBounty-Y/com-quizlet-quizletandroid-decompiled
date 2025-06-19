package com.quizlet.remote.model.union.studysetwithcreatorinclass;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.union.studysetwithcreatorinclass.StudySetWithCreatorInClassResponse;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class StudySetWithCreatorInClassResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;

    public StudySetWithCreatorInClassResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("models", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(StudySetWithCreatorInClassResponse.Models.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        StudySetWithCreatorInClassResponse.Models models = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        PagingInfo pagingInfo = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                models = (StudySetWithCreatorInClassResponse.Models) this.b.a(reader);
            } else if (iK0 == 1) {
                pagingInfo = (PagingInfo) this.c.a(reader);
                z = true;
            } else if (iK0 == 2) {
                list = (List) this.d.a(reader);
                z2 = true;
            } else if (iK0 == 3) {
                modelError = (ModelError) this.e.a(reader);
                z3 = true;
            }
        }
        reader.i();
        StudySetWithCreatorInClassResponse studySetWithCreatorInClassResponse = new StudySetWithCreatorInClassResponse(models);
        if (z) {
            studySetWithCreatorInClassResponse.a = pagingInfo;
        }
        if (z2) {
            studySetWithCreatorInClassResponse.b = list;
        }
        if (z3) {
            studySetWithCreatorInClassResponse.c = modelError;
        }
        return studySetWithCreatorInClassResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudySetWithCreatorInClassResponse studySetWithCreatorInClassResponse = (StudySetWithCreatorInClassResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studySetWithCreatorInClassResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, studySetWithCreatorInClassResponse.d);
        writer.l("paging");
        this.c.g(writer, studySetWithCreatorInClassResponse.a);
        writer.l("validationErrors");
        this.d.g(writer, studySetWithCreatorInClassResponse.b);
        writer.l("error");
        this.e.g(writer, studySetWithCreatorInClassResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(56, "GeneratedJsonAdapter(StudySetWithCreatorInClassResponse)", "toString(...)");
    }
}
