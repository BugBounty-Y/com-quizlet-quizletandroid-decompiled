package com.quizlet.remote.model.notes;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.user.RemoteUser;
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
public final class RemoteStudyNoteJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public volatile Constructor e;

    public RemoteStudyNoteJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "title", AssociationNames.CREATOR, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteUser.class, m, AssociationNames.CREATOR);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.class, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        RemoteUser remoteUser = null;
        Boolean bool = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                str = (String) this.b.a(reader);
            } else if (iK0 == 1) {
                str2 = (String) this.b.a(reader);
            } else if (iK0 == 2) {
                remoteUser = (RemoteUser) this.c.a(reader);
            } else if (iK0 == 3) {
                bool = (Boolean) this.d.a(reader);
                i = -9;
            }
        }
        reader.i();
        if (i == -9) {
            return new RemoteStudyNote(str, str2, remoteUser, bool);
        }
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteStudyNote.class.getDeclaredConstructor(String.class, String.class, RemoteUser.class, Boolean.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(str, str2, remoteUser, bool, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteStudyNote) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteStudyNote remoteStudyNote = (RemoteStudyNote) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteStudyNote == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        l lVar = this.b;
        lVar.g(writer, remoteStudyNote.a);
        writer.l("title");
        lVar.g(writer, remoteStudyNote.b);
        writer.l(AssociationNames.CREATOR);
        this.c.g(writer, remoteStudyNote.c);
        writer.l("isDeleted");
        this.d.g(writer, remoteStudyNote.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(RemoteStudyNote)", "toString(...)");
    }
}
