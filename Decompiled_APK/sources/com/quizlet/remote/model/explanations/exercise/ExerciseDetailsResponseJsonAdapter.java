package com.quizlet.remote.model.explanations.exercise;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.explanations.exercise.ExerciseDetailsResponse;
import com.quizlet.remote.model.metering.RemoteMeteringInfo;
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
public final class ExerciseDetailsResponseJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;

    public ExerciseDetailsResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("models", "metering", "isContentLimited", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(ExerciseDetailsResponse.Models.class, m, "models");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteMeteringInfo.class, m, "meteringInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.class, m, "isContentLimited");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        ExerciseDetailsResponse.Models models = null;
        Boolean bool = null;
        PagingInfo pagingInfo = null;
        List list = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        RemoteMeteringInfo remoteMeteringInfo = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    models = (ExerciseDetailsResponse.Models) this.b.a(reader);
                    break;
                case 1:
                    remoteMeteringInfo = (RemoteMeteringInfo) this.c.a(reader);
                    break;
                case 2:
                    bool = (Boolean) this.d.a(reader);
                    break;
                case 3:
                    pagingInfo = (PagingInfo) this.e.a(reader);
                    z = true;
                    break;
                case 4:
                    list = (List) this.f.a(reader);
                    z2 = true;
                    break;
                case 5:
                    modelError = (ModelError) this.g.a(reader);
                    z3 = true;
                    break;
            }
        }
        reader.i();
        ExerciseDetailsResponse exerciseDetailsResponse = new ExerciseDetailsResponse(models, remoteMeteringInfo, bool);
        if (z) {
            exerciseDetailsResponse.a = pagingInfo;
        }
        if (z2) {
            exerciseDetailsResponse.b = list;
        }
        if (z3) {
            exerciseDetailsResponse.c = modelError;
        }
        return exerciseDetailsResponse;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ExerciseDetailsResponse exerciseDetailsResponse = (ExerciseDetailsResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (exerciseDetailsResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("models");
        this.b.g(writer, exerciseDetailsResponse.d);
        writer.l("metering");
        this.c.g(writer, exerciseDetailsResponse.e);
        writer.l("isContentLimited");
        this.d.g(writer, exerciseDetailsResponse.f);
        writer.l("paging");
        this.e.g(writer, exerciseDetailsResponse.a);
        writer.l("validationErrors");
        this.f.g(writer, exerciseDetailsResponse.b);
        writer.l("error");
        this.g.g(writer, exerciseDetailsResponse.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(45, "GeneratedJsonAdapter(ExerciseDetailsResponse)", "toString(...)");
    }
}
