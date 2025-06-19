package com.quizlet.remote.model.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.base.ModelError;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.base.ValidationError;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.qclass.RemoteClass;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.term.RemoteTerm;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
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
public final class RemoteAllResultsModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public final l i;
    public final l j;
    public final l k;

    public RemoteAllResultsModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b(AssociationNames.CLASS, "set", "textbook", "explanationQuestion", "user", "term", "socialProof", "paging", "validationErrors", "error");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteClass.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "classes");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSet.class), m, "sets");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteTextbook.class), m, "textbooks");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, RemoteQuestion.class), m, "questions");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, RemoteUser.class), m, "users");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(H.f(List.class, RemoteTerm.class), m, "terms");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(H.f(List.class, RemoteSearchSocialSignalForSets.class), m, "socialSignalsForSets");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(PagingInfo.class, m, "pagingInfo");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
        l lVarA9 = moshi.a(H.f(List.class, ValidationError.class), m, "validationErrors");
        Intrinsics.checkNotNullExpressionValue(lVarA9, "adapter(...)");
        this.j = lVarA9;
        l lVarA10 = moshi.a(ModelError.class, m, "error");
        Intrinsics.checkNotNullExpressionValue(lVarA10, "adapter(...)");
        this.k = lVarA10;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        PagingInfo pagingInfo = null;
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        List list6 = null;
        List list7 = null;
        ModelError modelError = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        List list8 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    list = (List) this.b.a(reader);
                    break;
                case 1:
                    list2 = (List) this.c.a(reader);
                    break;
                case 2:
                    list3 = (List) this.d.a(reader);
                    break;
                case 3:
                    list4 = (List) this.e.a(reader);
                    break;
                case 4:
                    list5 = (List) this.f.a(reader);
                    break;
                case 5:
                    list6 = (List) this.g.a(reader);
                    break;
                case 6:
                    list7 = (List) this.h.a(reader);
                    break;
                case 7:
                    pagingInfo = (PagingInfo) this.i.a(reader);
                    z = true;
                    break;
                case 8:
                    list8 = (List) this.j.a(reader);
                    z2 = true;
                    break;
                case 9:
                    modelError = (ModelError) this.k.a(reader);
                    z3 = true;
                    break;
            }
        }
        reader.i();
        RemoteAllResultsModels remoteAllResultsModels = new RemoteAllResultsModels(list, list2, list3, list4, list5, list6, list7);
        if (z) {
            remoteAllResultsModels.a = pagingInfo;
        }
        if (z2) {
            remoteAllResultsModels.b = list8;
        }
        if (z3) {
            remoteAllResultsModels.c = modelError;
        }
        return remoteAllResultsModels;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteAllResultsModels remoteAllResultsModels = (RemoteAllResultsModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteAllResultsModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(AssociationNames.CLASS);
        this.b.g(writer, remoteAllResultsModels.d);
        writer.l("set");
        this.c.g(writer, remoteAllResultsModels.e);
        writer.l("textbook");
        this.d.g(writer, remoteAllResultsModels.f);
        writer.l("explanationQuestion");
        this.e.g(writer, remoteAllResultsModels.g);
        writer.l("user");
        this.f.g(writer, remoteAllResultsModels.h);
        writer.l("term");
        this.g.g(writer, remoteAllResultsModels.i);
        writer.l("socialProof");
        this.h.g(writer, remoteAllResultsModels.j);
        writer.l("paging");
        this.i.g(writer, remoteAllResultsModels.a);
        writer.l("validationErrors");
        this.j.g(writer, remoteAllResultsModels.b);
        writer.l("error");
        this.k.g(writer, remoteAllResultsModels.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(44, "GeneratedJsonAdapter(RemoteAllResultsModels)", "toString(...)");
    }
}
