package com.quizlet.remote.model.school;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
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
public final class RemoteNewSchoolJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteNewSchoolJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("name", "city", "state", DBUserFields.Names.COUNTRY_CODE);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(String.class, M.a, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("city", "city", reader);
                    }
                } else if (iK0 == 2) {
                    str3 = (String) lVar.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("state", "state", reader);
                    }
                } else if (iK0 == 3 && (str4 = (String) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k(DBUserFields.Names.COUNTRY_CODE, DBUserFields.Names.COUNTRY_CODE, reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("city", "city", reader);
        }
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("state", "state", reader);
        }
        if (str4 != null) {
            return new RemoteNewSchool(str, str2, str3, str4);
        }
        throw com.squareup.moshi.internal.b.e(DBUserFields.Names.COUNTRY_CODE, DBUserFields.Names.COUNTRY_CODE, reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteNewSchool remoteNewSchool = (RemoteNewSchool) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteNewSchool == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("name");
        l lVar = this.b;
        lVar.g(writer, remoteNewSchool.a);
        writer.l("city");
        lVar.g(writer, remoteNewSchool.b);
        writer.l("state");
        lVar.g(writer, remoteNewSchool.c);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar.g(writer, remoteNewSchool.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(37, "GeneratedJsonAdapter(RemoteNewSchool)", "toString(...)");
    }
}
