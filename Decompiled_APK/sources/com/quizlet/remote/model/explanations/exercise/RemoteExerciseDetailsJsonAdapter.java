package com.quizlet.remote.model.explanations.exercise;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.explanations.toc.RemoteExercise;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.internal.b;
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
public final class RemoteExerciseDetailsJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public final l i;
    public volatile Constructor j;

    public RemoteExerciseDetailsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "mediaExerciseId", "exerciseName", "chapterName", "chapterTitle", "groupTitle", "sectionName", "sectionTitle", "pageNumber", "_webUrl", "textbook", "solutions", "nextExercises", "previousExercises", "timestamp", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "mediaExerciseId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "chapterTitle");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(RemoteTextbook.class, m, "textbook");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(H.f(List.class, RemoteSolution.class), m, "solutions");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(H.f(List.class, RemoteExercise.class), m, "nextExercises");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(Long.class, m, "timestampSec");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i2 = -1;
        Boolean bool2 = bool;
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        RemoteTextbook remoteTextbook = null;
        List list = null;
        List list2 = null;
        List list3 = null;
        Long l2 = null;
        String str8 = null;
        String str9 = null;
        while (true) {
            Long l3 = l;
            String str10 = str;
            String str11 = str2;
            String str12 = str3;
            String str13 = str4;
            if (!reader.l()) {
                String str14 = str5;
                reader.i();
                if (i2 == -49153) {
                    if (l3 == null) {
                        throw b.e("id", "id", reader);
                    }
                    long jLongValue = l3.longValue();
                    if (str10 == null) {
                        throw b.e("mediaExerciseId", "mediaExerciseId", reader);
                    }
                    if (str11 == null) {
                        throw b.e("exercise", "exerciseName", reader);
                    }
                    if (str12 == null) {
                        throw b.e("chapterName", "chapterName", reader);
                    }
                    if (remoteTextbook == null) {
                        throw b.e("textbook", "textbook", reader);
                    }
                    if (list == null) {
                        throw b.e("solutions", "solutions", reader);
                    }
                    if (list2 == null) {
                        throw b.e("nextExercises", "nextExercises", reader);
                    }
                    if (list3 == null) {
                        throw b.e("previousExercises", "previousExercises", reader);
                    }
                    return new RemoteExerciseDetails(jLongValue, str10, str11, str12, str13, str14, str6, str8, str9, str7, remoteTextbook, list, list2, list3, l2, bool2.booleanValue());
                }
                Constructor declaredConstructor = this.j;
                if (declaredConstructor == null) {
                    i = i2;
                    declaredConstructor = RemoteExerciseDetails.class.getDeclaredConstructor(Long.TYPE, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, RemoteTextbook.class, List.class, List.class, List.class, Long.class, Boolean.TYPE, Integer.TYPE, b.c);
                    this.j = declaredConstructor;
                    Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
                } else {
                    i = i2;
                }
                Constructor constructor = declaredConstructor;
                if (l3 == null) {
                    throw b.e("id", "id", reader);
                }
                if (str10 == null) {
                    throw b.e("mediaExerciseId", "mediaExerciseId", reader);
                }
                if (str11 == null) {
                    throw b.e("exercise", "exerciseName", reader);
                }
                if (str12 == null) {
                    throw b.e("chapterName", "chapterName", reader);
                }
                if (remoteTextbook == null) {
                    throw b.e("textbook", "textbook", reader);
                }
                if (list == null) {
                    throw b.e("solutions", "solutions", reader);
                }
                if (list2 == null) {
                    throw b.e("nextExercises", "nextExercises", reader);
                }
                if (list3 == null) {
                    throw b.e("previousExercises", "previousExercises", reader);
                }
                Object objNewInstance = constructor.newInstance(l3, str10, str11, str12, str13, str14, str6, str8, str9, str7, remoteTextbook, list, list2, list3, l2, bool2, Integer.valueOf(i), null);
                Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
                return (RemoteExerciseDetails) objNewInstance;
            }
            String str15 = str5;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw b.k("id", "id", reader);
                    }
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 1:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw b.k("mediaExerciseId", "mediaExerciseId", reader);
                    }
                    l = l3;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 2:
                    str2 = (String) this.c.a(reader);
                    if (str2 == null) {
                        throw b.k("exercise", "exerciseName", reader);
                    }
                    l = l3;
                    str = str10;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 3:
                    str3 = (String) this.c.a(reader);
                    if (str3 == null) {
                        throw b.k("chapterName", "chapterName", reader);
                    }
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str4 = str13;
                    str5 = str15;
                case 4:
                    str4 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str5 = str15;
                case 5:
                    str5 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                case 6:
                    str6 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 7:
                    str8 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 8:
                    str9 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 9:
                    str7 = (String) this.d.a(reader);
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 10:
                    remoteTextbook = (RemoteTextbook) this.e.a(reader);
                    if (remoteTextbook == null) {
                        throw b.k("textbook", "textbook", reader);
                    }
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 11:
                    list = (List) this.f.a(reader);
                    if (list == null) {
                        throw b.k("solutions", "solutions", reader);
                    }
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 12:
                    list2 = (List) this.g.a(reader);
                    if (list2 == null) {
                        throw b.k("nextExercises", "nextExercises", reader);
                    }
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 13:
                    list3 = (List) this.g.a(reader);
                    if (list3 == null) {
                        throw b.k("previousExercises", "previousExercises", reader);
                    }
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 14:
                    l2 = (Long) this.h.a(reader);
                    i2 &= -16385;
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                case 15:
                    bool2 = (Boolean) this.i.a(reader);
                    if (bool2 == null) {
                        throw b.k("isDeleted", "isDeleted", reader);
                    }
                    i2 &= -32769;
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
                default:
                    l = l3;
                    str = str10;
                    str2 = str11;
                    str3 = str12;
                    str4 = str13;
                    str5 = str15;
            }
        }
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteExerciseDetails remoteExerciseDetails = (RemoteExerciseDetails) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteExerciseDetails == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteExerciseDetails.a));
        writer.l("mediaExerciseId");
        l lVar = this.c;
        lVar.g(writer, remoteExerciseDetails.b);
        writer.l("exerciseName");
        lVar.g(writer, remoteExerciseDetails.c);
        writer.l("chapterName");
        lVar.g(writer, remoteExerciseDetails.d);
        writer.l("chapterTitle");
        l lVar2 = this.d;
        lVar2.g(writer, remoteExerciseDetails.e);
        writer.l("groupTitle");
        lVar2.g(writer, remoteExerciseDetails.f);
        writer.l("sectionName");
        lVar2.g(writer, remoteExerciseDetails.g);
        writer.l("sectionTitle");
        lVar2.g(writer, remoteExerciseDetails.h);
        writer.l("pageNumber");
        lVar2.g(writer, remoteExerciseDetails.i);
        writer.l("_webUrl");
        lVar2.g(writer, remoteExerciseDetails.j);
        writer.l("textbook");
        this.e.g(writer, remoteExerciseDetails.k);
        writer.l("solutions");
        this.f.g(writer, remoteExerciseDetails.l);
        writer.l("nextExercises");
        l lVar3 = this.g;
        lVar3.g(writer, remoteExerciseDetails.m);
        writer.l("previousExercises");
        lVar3.g(writer, remoteExerciseDetails.n);
        writer.l("timestamp");
        this.h.g(writer, remoteExerciseDetails.o);
        writer.l("isDeleted");
        this.i.g(writer, Boolean.valueOf(remoteExerciseDetails.p));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(43, "GeneratedJsonAdapter(RemoteExerciseDetails)", "toString(...)");
    }
}
