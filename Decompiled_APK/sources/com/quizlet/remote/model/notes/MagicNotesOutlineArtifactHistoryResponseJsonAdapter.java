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
public final class MagicNotesOutlineArtifactHistoryResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public volatile Constructor c;

    public MagicNotesOutlineArtifactHistoryResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("user_edited");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(Boolean.TYPE, M.a, "userEdited");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
                if (bool == null) {
                    throw com.squareup.moshi.internal.b.k("userEdited", "user_edited", reader);
                }
                i = -2;
            } else {
                continue;
            }
        }
        reader.i();
        if (i == -2) {
            return new MagicNotesOutlineArtifactHistoryResponse(bool.booleanValue());
        }
        Constructor declaredConstructor = this.c;
        if (declaredConstructor == null) {
            declaredConstructor = MagicNotesOutlineArtifactHistoryResponse.class.getDeclaredConstructor(Boolean.TYPE, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.c = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(bool, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (MagicNotesOutlineArtifactHistoryResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        MagicNotesOutlineArtifactHistoryResponse magicNotesOutlineArtifactHistoryResponse = (MagicNotesOutlineArtifactHistoryResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (magicNotesOutlineArtifactHistoryResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("user_edited");
        this.b.g(writer, Boolean.valueOf(magicNotesOutlineArtifactHistoryResponse.a));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(62, "GeneratedJsonAdapter(MagicNotesOutlineArtifactHistoryResponse)", "toString(...)");
    }
}
