package com.quizlet.remote.model.school;

import com.appsflyer.AdRevenueScheme;
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
public final class RemoteSchoolJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;

    public RemoteSchoolJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "city", AdRevenueScheme.COUNTRY, DBUserFields.Names.COUNTRY_CODE, "lastModified", "latitude", "level", "longitude", "name", "state");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "city");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.class, m, "lastModified");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Double.class, m, "latitude");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        Integer num = null;
        Double d = null;
        Integer num2 = null;
        Double d2 = null;
        String str4 = null;
        String str5 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.d;
            Long l2 = l;
            l lVar2 = this.e;
            l lVar3 = this.c;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    continue;
                case 1:
                    str = (String) lVar3.a(reader);
                    break;
                case 2:
                    str2 = (String) lVar3.a(reader);
                    break;
                case 3:
                    str3 = (String) lVar3.a(reader);
                    break;
                case 4:
                    num = (Integer) lVar.a(reader);
                    break;
                case 5:
                    d = (Double) lVar2.a(reader);
                    break;
                case 6:
                    num2 = (Integer) lVar.a(reader);
                    break;
                case 7:
                    d2 = (Double) lVar2.a(reader);
                    break;
                case 8:
                    str4 = (String) this.f.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    break;
                case 9:
                    str5 = (String) lVar3.a(reader);
                    break;
            }
            l = l2;
        }
        Long l3 = l;
        reader.i();
        if (l3 == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        long jLongValue = l3.longValue();
        if (str4 != null) {
            return new RemoteSchool(jLongValue, str, str2, str3, num, d, num2, d2, str4, str5);
        }
        throw com.squareup.moshi.internal.b.e("name", "name", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSchool remoteSchool = (RemoteSchool) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSchool == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteSchool.a));
        writer.l("city");
        l lVar = this.c;
        lVar.g(writer, remoteSchool.b);
        writer.l(AdRevenueScheme.COUNTRY);
        lVar.g(writer, remoteSchool.c);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar.g(writer, remoteSchool.d);
        writer.l("lastModified");
        l lVar2 = this.d;
        lVar2.g(writer, remoteSchool.e);
        writer.l("latitude");
        l lVar3 = this.e;
        lVar3.g(writer, remoteSchool.f);
        writer.l("level");
        lVar2.g(writer, remoteSchool.g);
        writer.l("longitude");
        lVar3.g(writer, remoteSchool.h);
        writer.l("name");
        this.f.g(writer, remoteSchool.i);
        writer.l("state");
        lVar.g(writer, remoteSchool.j);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(RemoteSchool)", "toString(...)");
    }
}
