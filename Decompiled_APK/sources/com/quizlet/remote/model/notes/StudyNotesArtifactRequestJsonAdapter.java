package com.quizlet.remote.model.notes;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesArtifactRequestJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public volatile Constructor d;

    public StudyNotesArtifactRequestJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("aiEdited", "content");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Boolean.TYPE, m, "aiEdited");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "content");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        String str = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("aiEdited", "aiEdited", reader);
                }
                i = -2;
            } else if (iK0 == 1 && (str = (String) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("content", "content", reader);
            }
        }
        reader.i();
        if (i == -2) {
            boolean zBooleanValue = bool.booleanValue();
            if (str != null) {
                return new StudyNotesArtifactRequest(zBooleanValue, str);
            }
            throw com.squareup.moshi.internal.b.e("content", "content", reader);
        }
        Constructor declaredConstructor = this.d;
        if (declaredConstructor == null) {
            declaredConstructor = StudyNotesArtifactRequest.class.getDeclaredConstructor(Boolean.TYPE, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.d = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("content", "content", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(bool, str, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (StudyNotesArtifactRequest) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        StudyNotesArtifactRequest studyNotesArtifactRequest = (StudyNotesArtifactRequest) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (studyNotesArtifactRequest == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("aiEdited");
        this.b.g(writer, Boolean.valueOf(studyNotesArtifactRequest.a));
        writer.l("content");
        this.c.g(writer, studyNotesArtifactRequest.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(StudyNotesArtifactRequest)", "toString(...)");
    }
}
