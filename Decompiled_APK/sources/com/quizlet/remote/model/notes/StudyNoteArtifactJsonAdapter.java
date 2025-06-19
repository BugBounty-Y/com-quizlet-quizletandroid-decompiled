package com.quizlet.remote.model.notes;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
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
public final class StudyNoteArtifactJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public volatile Constructor c;

    public StudyNoteArtifactJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("studyNotesArtifacts");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, MagicNotesArtifactResponse.class), M.a, "artifact");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
                if (list == null) {
                    throw com.squareup.moshi.internal.b.k("artifact", "studyNotesArtifacts", reader);
                }
                i = -2;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -2) {
            Intrinsics.e(list, "null cannot be cast to non-null type kotlin.collections.List<com.quizlet.remote.model.notes.MagicNotesArtifactResponse>");
            return new StudyNoteArtifact(list);
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = StudyNoteArtifact.class.getDeclaredConstructor(List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (StudyNoteArtifact) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudyNoteArtifact studyNoteArtifact = (StudyNoteArtifact) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studyNoteArtifact == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("studyNotesArtifacts");
        this.b.g(writer, studyNoteArtifact.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(StudyNoteArtifact)", "toString(...)");
    }
}
