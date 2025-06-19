package com.quizlet.remote.model.qclass;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.remote.model.school.RemoteSchool;
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
public final class ClassModelsJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public ClassModelsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b(AssociationNames.CLASS, "school");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        Util$ParameterizedTypeImpl util$ParameterizedTypeImplF = H.f(List.class, RemoteClass.class);
        M m = M.a;
        l lVarA = moshi.a(util$ParameterizedTypeImplF, m, "classList");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, RemoteSchool.class), m, "schoolList");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        List list2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                list = (List) this.b.a(reader);
            } else if (iK0 == 1) {
                list2 = (List) this.c.a(reader);
            }
        }
        reader.i();
        return new ClassModels(list, list2);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        ClassModels classModels = (ClassModels) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (classModels == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l(AssociationNames.CLASS);
        this.b.g(writer, classModels.a);
        writer.l("school");
        this.c.g(writer, classModels.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(33, "GeneratedJsonAdapter(ClassModels)", "toString(...)");
    }
}
