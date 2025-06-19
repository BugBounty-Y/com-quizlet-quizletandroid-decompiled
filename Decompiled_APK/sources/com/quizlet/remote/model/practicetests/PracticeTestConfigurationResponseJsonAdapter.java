package com.quizlet.remote.model.practicetests;

import com.google.android.gms.measurement.internal.Z;
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
public final class PracticeTestConfigurationResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public volatile Constructor g;

    public PracticeTestConfigurationResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionCount", "questionFormats", "testTimer", "testView", "enableTestTimer", "enableTimerSound", "mediaTypes", "contentFormats");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "questionCount");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(H.f(List.class, String.class), m, "questionFormats");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "testTimer");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "testView");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Boolean.TYPE, m, "enableTestTimer");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        Integer num = null;
        List list = null;
        Long l = null;
        String str = null;
        Boolean bool = null;
        Boolean bool2 = null;
        List list2 = null;
        List list3 = null;
        while (reader.l()) {
            Integer num2 = num;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    num = (Integer) this.b.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("questionCount", "questionCount", reader);
                    }
                    continue;
                case 1:
                    list = (List) this.c.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("questionFormats", "questionFormats", reader);
                    }
                    break;
                case 2:
                    l = (Long) this.d.a(reader);
                    break;
                case 3:
                    str = (String) this.e.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("testView", "testView", reader);
                    }
                    break;
                case 4:
                    bool = (Boolean) this.f.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("enableTestTimer", "enableTestTimer", reader);
                    }
                    break;
                case 5:
                    bool2 = (Boolean) this.f.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("enableTimerSound", "enableTimerSound", reader);
                    }
                    break;
                case 6:
                    list2 = (List) this.c.a(reader);
                    if (list2 == null) {
                        throw com.squareup.moshi.internal.b.k("mediaTypes", "mediaTypes", reader);
                    }
                    i &= -65;
                    break;
                case 7:
                    list3 = (List) this.c.a(reader);
                    if (list3 == null) {
                        throw com.squareup.moshi.internal.b.k("contentFormats", "contentFormats", reader);
                    }
                    i &= -129;
                    break;
            }
            num = num2;
        }
        Integer num3 = num;
        reader.i();
        if (i == -193) {
            Boolean bool3 = bool2;
            String str2 = str;
            List list4 = list;
            if (num3 == null) {
                throw com.squareup.moshi.internal.b.e("questionCount", "questionCount", reader);
            }
            Boolean bool4 = bool;
            Long l2 = l;
            int iIntValue = num3.intValue();
            if (list4 == null) {
                throw com.squareup.moshi.internal.b.e("questionFormats", "questionFormats", reader);
            }
            if (str2 == null) {
                throw com.squareup.moshi.internal.b.e("testView", "testView", reader);
            }
            if (bool4 == null) {
                throw com.squareup.moshi.internal.b.e("enableTestTimer", "enableTestTimer", reader);
            }
            boolean zBooleanValue = bool4.booleanValue();
            if (bool3 == null) {
                throw com.squareup.moshi.internal.b.e("enableTimerSound", "enableTimerSound", reader);
            }
            boolean zBooleanValue2 = bool3.booleanValue();
            Intrinsics.e(list2, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>");
            Intrinsics.e(list3, "null cannot be cast to non-null type kotlin.collections.List<kotlin.String>");
            return new PracticeTestConfigurationResponse(iIntValue, list4, l2, str2, zBooleanValue, zBooleanValue2, list2, list3);
        }
        Boolean bool5 = bool;
        Boolean bool6 = bool2;
        Long l3 = l;
        String str3 = str;
        List list5 = list;
        Constructor declaredConstructor = this.g;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Boolean.TYPE;
            Class cls3 = Integer.TYPE;
            declaredConstructor = PracticeTestConfigurationResponse.class.getDeclaredConstructor(cls3, List.class, Long.class, String.class, cls2, cls2, List.class, List.class, cls3, cls);
            this.g = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (num3 == null) {
            throw com.squareup.moshi.internal.b.e("questionCount", "questionCount", reader);
        }
        if (list5 == null) {
            throw com.squareup.moshi.internal.b.e("questionFormats", "questionFormats", reader);
        }
        if (str3 == null) {
            throw com.squareup.moshi.internal.b.e("testView", "testView", reader);
        }
        if (bool5 == null) {
            throw com.squareup.moshi.internal.b.e("enableTestTimer", "enableTestTimer", reader);
        }
        if (bool6 == null) {
            throw com.squareup.moshi.internal.b.e("enableTimerSound", "enableTimerSound", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(num3, list5, l3, str3, bool5, bool6, list2, list3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (PracticeTestConfigurationResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestConfigurationResponse practiceTestConfigurationResponse = (PracticeTestConfigurationResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestConfigurationResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionCount");
        this.b.g(writer, Integer.valueOf(practiceTestConfigurationResponse.a));
        writer.l("questionFormats");
        l lVar = this.c;
        lVar.g(writer, practiceTestConfigurationResponse.b);
        writer.l("testTimer");
        this.d.g(writer, practiceTestConfigurationResponse.c);
        writer.l("testView");
        this.e.g(writer, practiceTestConfigurationResponse.d);
        writer.l("enableTestTimer");
        Boolean boolValueOf = Boolean.valueOf(practiceTestConfigurationResponse.e);
        l lVar2 = this.f;
        lVar2.g(writer, boolValueOf);
        writer.l("enableTimerSound");
        Z.q(practiceTestConfigurationResponse.f, lVar2, writer, "mediaTypes");
        lVar.g(writer, practiceTestConfigurationResponse.g);
        writer.l("contentFormats");
        lVar.g(writer, practiceTestConfigurationResponse.h);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(55, "GeneratedJsonAdapter(PracticeTestConfigurationResponse)", "toString(...)");
    }
}
