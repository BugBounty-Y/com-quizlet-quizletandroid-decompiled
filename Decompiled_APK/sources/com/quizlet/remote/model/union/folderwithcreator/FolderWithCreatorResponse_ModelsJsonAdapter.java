package com.quizlet.remote.model.union.folderwithcreator;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.union.folderwithcreator.FolderWithCreatorResponse;
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
public final class FolderWithCreatorResponse_ModelsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public FolderWithCreatorResponse_ModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("folder", "user", "course", "school");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteFolder.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "folder");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteUser.class), m, "user");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(H.f(List.class, RemoteCourse.class), m, "course");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(H.f(List.class, RemoteSchool.class), m, "school");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        List list3 = null;
        List list4 = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
            } else if (iK0 == 2) {
                list3 = (List) this.d.a(reader);
                i &= -5;
            } else if (iK0 == 3) {
                list4 = (List) this.e.a(reader);
                i &= -9;
            }
        }
        reader.i();
        if (i == -13) {
            return new FolderWithCreatorResponse.Models(list, list2, list3, list4);
        }
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            declaredConstructor = FolderWithCreatorResponse.Models.class.getDeclaredConstructor(List.class, List.class, List.class, List.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(list, list2, list3, list4, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (FolderWithCreatorResponse.Models) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderWithCreatorResponse.Models models = (FolderWithCreatorResponse.Models) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (models == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("folder");
        this.b.g(writer, models.a);
        writer.l("user");
        this.c.g(writer, models.b);
        writer.l("course");
        this.d.g(writer, models.c);
        writer.l("school");
        this.e.g(writer, models.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(54, "GeneratedJsonAdapter(FolderWithCreatorResponse.Models)", "toString(...)");
    }
}
