package com.quizlet.remote.model.notes;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.Util$ParameterizedTypeImpl;
import com.squareup.moshi.l;
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
public final class StudyNoteModelJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public volatile Constructor e;

    public StudyNoteModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("magicNote", "artifact", "user");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, MagicNotesResponse.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "magicNotes");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, MagicNotesArtifactResponse.class), m, "artifacts");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteUser.class), m, "users");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("magicNotes", "magicNote", reader);
                }
                i &= -2;
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
                if (list2 == null) {
                    throw com.squareup.moshi.internal.b.k("artifacts", "artifact", reader);
                }
                i &= -3;
            } else if (iK0 == 2) {
                list3 = (List) this.d.a(reader);
                if (list3 == null) {
                    throw com.squareup.moshi.internal.b.k("users", "user", reader);
                }
                i &= -5;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -8) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.notes.MagicNotesResponse>");
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.notes.MagicNotesArtifactResponse>");
            Intrinsics.e(list3, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.user.RemoteUser>");
            return new StudyNoteModel(list, list2, list3);
        }
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            declaredConstructor = StudyNoteModel.class.getDeclaredConstructor(List.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, list2, list3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (StudyNoteModel) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudyNoteModel studyNoteModel = (StudyNoteModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studyNoteModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("magicNote");
        this.b.g(writer, studyNoteModel.a);
        writer.l("artifact");
        this.c.g(writer, studyNoteModel.b);
        writer.l("user");
        this.d.g(writer, studyNoteModel.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(StudyNoteModel)", "toString(...)");
    }
}
