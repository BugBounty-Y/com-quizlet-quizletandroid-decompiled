package com.quizlet.remote.model.practicetests;

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
public final class PracticeTestConfigurationJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public volatile Constructor g;

    public PracticeTestConfigurationJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("questionCount", "questionFormats", "testTimer", "testView", "enableTestTimer", "enableTimerSound");
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
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        Boolean bool2 = bool;
        Boolean bool3 = bool2;
        Integer num = null;
        List list = null;
        Long l = null;
        String str = null;
        while (reader.l()) {
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
                    break;
                case 1:
                    list = (List) this.c.a(reader);
                    if (list == null) {
                        throw com.squareup.moshi.internal.b.k("questionFormats", "questionFormats", reader);
                    }
                    break;
                case 2:
                    l = (Long) this.d.a(reader);
                    i &= -5;
                    break;
                case 3:
                    str = (String) this.e.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("testView", "testView", reader);
                    }
                    i &= -9;
                    break;
                case 4:
                    bool2 = (Boolean) this.f.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("enableTestTimer", "enableTestTimer", reader);
                    }
                    i &= -17;
                    break;
                case 5:
                    bool3 = (Boolean) this.f.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("enableTimerSound", "enableTimerSound", reader);
                    }
                    i &= -33;
                    break;
            }
        }
        reader.i();
        if (i == -61) {
            if (num == null) {
                throw com.squareup.moshi.internal.b.e("questionCount", "questionCount", reader);
            }
            int iIntValue = num.intValue();
            if (list == null) {
                throw com.squareup.moshi.internal.b.e("questionFormats", "questionFormats", reader);
            }
            Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
            return new PracticeTestConfiguration(iIntValue, list, l, str, bool2.booleanValue(), bool3.booleanValue());
        }
        Constructor declaredConstructor = this.g;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Integer.TYPE;
            Class cls3 = Boolean.TYPE;
            declaredConstructor = PracticeTestConfiguration.class.getDeclaredConstructor(cls2, List.class, Long.class, String.class, cls3, cls3, cls2, cls);
            this.g = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("questionCount", "questionCount", reader);
        }
        if (list == null) {
            throw com.squareup.moshi.internal.b.e("questionFormats", "questionFormats", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(num, list, l, str, bool2, bool3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (PracticeTestConfiguration) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        PracticeTestConfiguration practiceTestConfiguration = (PracticeTestConfiguration) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (practiceTestConfiguration == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("questionCount");
        this.b.g(writer, Integer.valueOf(practiceTestConfiguration.a));
        writer.l("questionFormats");
        this.c.g(writer, practiceTestConfiguration.b);
        writer.l("testTimer");
        this.d.g(writer, practiceTestConfiguration.c);
        writer.l("testView");
        this.e.g(writer, practiceTestConfiguration.d);
        writer.l("enableTestTimer");
        Boolean boolValueOf = Boolean.valueOf(practiceTestConfiguration.e);
        l lVar = this.f;
        lVar.g(writer, boolValueOf);
        writer.l("enableTimerSound");
        lVar.g(writer, Boolean.valueOf(practiceTestConfiguration.f));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(PracticeTestConfiguration)", "toString(...)");
    }
}
