package com.quizlet.remote.model.set;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteQpfBreadcrumbsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteQpfBreadcrumbsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("courseCode", "folderLinkPath", "folderId", "schoolName", DBGroupFields.Names.SCHOOL_ID, "courseId");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "courseCode");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.class, m, "folderId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        Long l = null;
        String str3 = null;
        Long l2 = null;
        Long l3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.b;
            l lVar2 = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) lVar.a(reader);
                    break;
                case 1:
                    str2 = (String) lVar.a(reader);
                    break;
                case 2:
                    l = (Long) lVar2.a(reader);
                    break;
                case 3:
                    str3 = (String) lVar.a(reader);
                    break;
                case 4:
                    l2 = (Long) lVar2.a(reader);
                    break;
                case 5:
                    l3 = (Long) lVar2.a(reader);
                    break;
            }
        }
        reader.i();
        return new RemoteQpfBreadcrumbs(str, str2, l, str3, l2, l3);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteQpfBreadcrumbs remoteQpfBreadcrumbs = (RemoteQpfBreadcrumbs) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteQpfBreadcrumbs == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseCode");
        l lVar = this.b;
        lVar.g(writer, remoteQpfBreadcrumbs.a);
        writer.l("folderLinkPath");
        lVar.g(writer, remoteQpfBreadcrumbs.b);
        writer.l("folderId");
        l lVar2 = this.c;
        lVar2.g(writer, remoteQpfBreadcrumbs.c);
        writer.l("schoolName");
        lVar.g(writer, remoteQpfBreadcrumbs.d);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        lVar2.g(writer, remoteQpfBreadcrumbs.e);
        writer.l("courseId");
        lVar2.g(writer, remoteQpfBreadcrumbs.f);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(RemoteQpfBreadcrumbs)", "toString(...)");
    }
}
