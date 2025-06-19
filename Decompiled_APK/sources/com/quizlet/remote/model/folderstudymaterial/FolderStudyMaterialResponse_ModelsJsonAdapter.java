package com.quizlet.remote.model.folderstudymaterial;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.exercise.RemoteExerciseDetails;
import com.quizlet.remote.model.explanations.question.RemoteQuestion;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse;
import com.quizlet.remote.model.notes.RemoteStudyNote;
import com.quizlet.remote.model.set.RemoteSet;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterialResponse_ModelsJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public final com.squareup.moshi.l g;
    public final com.squareup.moshi.l h;
    public final com.squareup.moshi.l i;
    public volatile Constructor j;

    public FolderStudyMaterialResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("folderStudyMaterial", "explanationQuestion", "folder", "set", "studyNote", "textbook", "textbookExercise", "user");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteFolderStudyMaterial.class);
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "folderStudyMaterial");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(H.f(List.class, RemoteQuestion.class), m, "explanationQuestion");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(H.f(List.class, RemoteFolder.class), m, "folder");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(H.f(List.class, RemoteSet.class), m, "set");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(H.f(List.class, RemoteStudyNote.class), m, "studyNote");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        com.squareup.moshi.l lVarA6 = moshi.a(H.f(List.class, RemoteTextbook.class), m, "textbook");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        com.squareup.moshi.l lVarA7 = moshi.a(H.f(List.class, RemoteExerciseDetails.class), m, "textbookExercise");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        com.squareup.moshi.l lVarA8 = moshi.a(H.f(List.class, RemoteUser.class), m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        List list5 = null;
        List list6 = null;
        List list7 = null;
        List list8 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    list = (List) this.b.a(reader);
                    i &= -2;
                    break;
                case 1:
                    list2 = (List) this.c.a(reader);
                    i &= -3;
                    break;
                case 2:
                    list3 = (List) this.d.a(reader);
                    i &= -5;
                    break;
                case 3:
                    list4 = (List) this.e.a(reader);
                    i &= -9;
                    break;
                case 4:
                    list5 = (List) this.f.a(reader);
                    i &= -17;
                    break;
                case 5:
                    list6 = (List) this.g.a(reader);
                    i &= -33;
                    break;
                case 6:
                    list7 = (List) this.h.a(reader);
                    i &= -65;
                    break;
                case 7:
                    list8 = (List) this.i.a(reader);
                    i &= -129;
                    break;
            }
        }
        reader.i();
        if (i == -256) {
            List list9 = list8;
            List list10 = list7;
            List list11 = list6;
            List list12 = list5;
            List list13 = list4;
            return new FolderStudyMaterialResponse.Models(list, list2, list3, list13, list12, list11, list10, list9);
        }
        List list14 = list8;
        List list15 = list7;
        List list16 = list6;
        List list17 = list5;
        List list18 = list4;
        List list19 = list3;
        List list20 = list2;
        List list21 = list;
        Constructor declaredConstructor = this.j;
        if (declaredConstructor == null) {
            declaredConstructor = FolderStudyMaterialResponse.Models.class.getDeclaredConstructor(List.class, List.class, List.class, List.class, List.class, List.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.j = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list21, list20, list19, list18, list17, list16, list15, list14, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (FolderStudyMaterialResponse.Models) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderStudyMaterialResponse.Models models = (FolderStudyMaterialResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("folderStudyMaterial");
        this.b.g(writer, models.a);
        writer.l("explanationQuestion");
        this.c.g(writer, models.b);
        writer.l("folder");
        this.d.g(writer, models.c);
        writer.l("set");
        this.e.g(writer, models.d);
        writer.l("studyNote");
        this.f.g(writer, models.e);
        writer.l("textbook");
        this.g.g(writer, models.f);
        writer.l("textbookExercise");
        this.h.g(writer, models.g);
        writer.l("user");
        this.i.g(writer, models.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(56, "GeneratedJsonAdapter(FolderStudyMaterialResponse.Models)", "toString(...)");
    }
}
