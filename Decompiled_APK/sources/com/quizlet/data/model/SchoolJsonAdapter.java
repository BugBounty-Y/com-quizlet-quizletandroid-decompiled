package com.quizlet.data.model;

import com.appsflyer.AdRevenueScheme;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class SchoolJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public volatile Constructor g;

    public SchoolJsonAdapter(@NotNull com.squareup.moshi.D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "city", AdRevenueScheme.COUNTRY, DBUserFields.Names.COUNTRY_CODE, "lastModified", "latitude", "level", "longitude", "name", "state");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        kotlin.collections.M m = kotlin.collections.M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "city");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Integer.class, m, "lastModified");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Double.class, m, "latitude");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
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
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("id", "id", reader);
                    }
                    break;
                case 1:
                    str = (String) this.c.a(reader);
                    break;
                case 2:
                    str2 = (String) this.c.a(reader);
                    break;
                case 3:
                    str3 = (String) this.c.a(reader);
                    break;
                case 4:
                    num = (Integer) this.d.a(reader);
                    i &= -17;
                    break;
                case 5:
                    d = (Double) this.e.a(reader);
                    i &= -33;
                    break;
                case 6:
                    num2 = (Integer) this.d.a(reader);
                    i &= -65;
                    break;
                case 7:
                    d2 = (Double) this.e.a(reader);
                    i &= -129;
                    break;
                case 8:
                    str4 = (String) this.f.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k("name", "name", reader);
                    }
                    break;
                case 9:
                    str5 = (String) this.c.a(reader);
                    break;
            }
        }
        reader.i();
        if (i == -241) {
            Integer num3 = num;
            String str6 = str;
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("id", "id", reader);
            }
            Integer num4 = num2;
            String str7 = str3;
            Double d3 = d;
            String str8 = str2;
            long jLongValue = l.longValue();
            if (str4 != null) {
                return new School(jLongValue, str6, str8, str7, num3, d3, num4, d2, str4, str5);
            }
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        Integer num5 = num2;
        String str9 = str3;
        Integer num6 = num;
        String str10 = str;
        Double d4 = d;
        String str11 = str2;
        Constructor declaredConstructor = this.g;
        if (declaredConstructor == null) {
            declaredConstructor = School.class.getDeclaredConstructor(Long.TYPE, String.class, String.class, String.class, Integer.class, Double.class, Integer.class, Double.class, String.class, String.class, Integer.TYPE, com.squareup.moshi.internal.b.c);
            this.g = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        if (str4 == null) {
            throw com.squareup.moshi.internal.b.e("name", "name", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, str10, str11, str9, num6, d4, num5, d2, str4, str5, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (School) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(com.squareup.moshi.w writer, Object obj) {
        School school = (School) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (school == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(school.a));
        writer.l("city");
        com.squareup.moshi.l lVar = this.c;
        lVar.g(writer, school.b);
        writer.l(AdRevenueScheme.COUNTRY);
        lVar.g(writer, school.c);
        writer.l(DBUserFields.Names.COUNTRY_CODE);
        lVar.g(writer, school.d);
        writer.l("lastModified");
        com.squareup.moshi.l lVar2 = this.d;
        lVar2.g(writer, school.e);
        writer.l("latitude");
        com.squareup.moshi.l lVar3 = this.e;
        lVar3.g(writer, school.f);
        writer.l("level");
        lVar2.g(writer, school.g);
        writer.l("longitude");
        lVar3.g(writer, school.h);
        writer.l("name");
        this.f.g(writer, school.i);
        writer.l("state");
        lVar.g(writer, school.j);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(28, "GeneratedJsonAdapter(School)", "toString(...)");
    }
}
