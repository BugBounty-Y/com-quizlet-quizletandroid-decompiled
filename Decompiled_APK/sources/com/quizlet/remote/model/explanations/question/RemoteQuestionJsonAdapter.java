package com.quizlet.remote.model.explanations.question;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
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
public final class RemoteQuestionJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public final l h;
    public final l i;
    public final l j;
    public volatile Constructor k;

    public RemoteQuestionJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "slug", "mediaExerciseId", "prompt", "questionUuid", "answersCount", "subjectIds", "_webUrl", "solutions", "timestamp", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "slug");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "mediaExerciseId");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(RemoteQuestionPrompt.class, m, "prompt");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Integer.class, m, "answersCount");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(H.f(List.class, Integer.class), m, "subjectIds");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(H.f(List.class, RemoteSolution.class), m, "solutions");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(Long.class, m, "timestampSec");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
        l lVarA9 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA9, "adapter(...)");
        this.j = lVarA9;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        Boolean bool2 = bool;
        Long l = null;
        Long l2 = null;
        String str = null;
        String str2 = null;
        RemoteQuestionPrompt remoteQuestionPrompt = null;
        String str3 = null;
        Integer num = null;
        List list = null;
        String str4 = null;
        List list2 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    l = (Long) this.b.a(reader);
                    if (l == null) {
                        throw b.k("id", "id", reader);
                    }
                    break;
                case 1:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw b.k("slug", "slug", reader);
                    }
                    break;
                case 2:
                    str2 = (String) this.d.a(reader);
                    break;
                case 3:
                    remoteQuestionPrompt = (RemoteQuestionPrompt) this.e.a(reader);
                    if (remoteQuestionPrompt == null) {
                        throw b.k("prompt", "prompt", reader);
                    }
                    break;
                case 4:
                    str3 = (String) this.c.a(reader);
                    if (str3 == null) {
                        throw b.k("questionUuid", "questionUuid", reader);
                    }
                    break;
                case 5:
                    num = (Integer) this.f.a(reader);
                    break;
                case 6:
                    list = (List) this.g.a(reader);
                    if (list == null) {
                        throw b.k("subjectIds", "subjectIds", reader);
                    }
                    break;
                case 7:
                    str4 = (String) this.d.a(reader);
                    break;
                case 8:
                    list2 = (List) this.h.a(reader);
                    if (list2 == null) {
                        throw b.k("solutions", "solutions", reader);
                    }
                    break;
                case 9:
                    l2 = (Long) this.i.a(reader);
                    i &= -513;
                    break;
                case 10:
                    bool2 = (Boolean) this.j.a(reader);
                    if (bool2 == null) {
                        throw b.k("isDeleted", "isDeleted", reader);
                    }
                    i &= -1025;
                    break;
            }
        }
        reader.i();
        if (i == -1537) {
            if (l == null) {
                throw b.e("id", "id", reader);
            }
            long jLongValue = l.longValue();
            if (str == null) {
                throw b.e("slug", "slug", reader);
            }
            if (remoteQuestionPrompt == null) {
                throw b.e("prompt", "prompt", reader);
            }
            if (str3 == null) {
                throw b.e("questionUuid", "questionUuid", reader);
            }
            if (list == null) {
                throw b.e("subjectIds", "subjectIds", reader);
            }
            if (list2 == null) {
                throw b.e("solutions", "solutions", reader);
            }
            return new RemoteQuestion(jLongValue, str, str2, remoteQuestionPrompt, str3, num, list, str4, list2, l2, bool2.booleanValue());
        }
        Constructor declaredConstructor = this.k;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteQuestion.class.getDeclaredConstructor(Long.TYPE, String.class, String.class, RemoteQuestionPrompt.class, String.class, Integer.class, List.class, String.class, List.class, Long.class, Boolean.TYPE, Integer.TYPE, b.c);
            this.k = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw b.e("id", "id", reader);
        }
        if (str == null) {
            throw b.e("slug", "slug", reader);
        }
        if (remoteQuestionPrompt == null) {
            throw b.e("prompt", "prompt", reader);
        }
        if (str3 == null) {
            throw b.e("questionUuid", "questionUuid", reader);
        }
        if (list == null) {
            throw b.e("subjectIds", "subjectIds", reader);
        }
        if (list2 == null) {
            throw b.e("solutions", "solutions", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, str, str2, remoteQuestionPrompt, str3, num, list, str4, list2, l2, bool2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteQuestion) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteQuestion remoteQuestion = (RemoteQuestion) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteQuestion == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteQuestion.a));
        writer.l("slug");
        l lVar = this.c;
        lVar.g(writer, remoteQuestion.b);
        writer.l("mediaExerciseId");
        l lVar2 = this.d;
        lVar2.g(writer, remoteQuestion.c);
        writer.l("prompt");
        this.e.g(writer, remoteQuestion.d);
        writer.l("questionUuid");
        lVar.g(writer, remoteQuestion.e);
        writer.l("answersCount");
        this.f.g(writer, remoteQuestion.f);
        writer.l("subjectIds");
        this.g.g(writer, remoteQuestion.g);
        writer.l("_webUrl");
        lVar2.g(writer, remoteQuestion.h);
        writer.l("solutions");
        this.h.g(writer, remoteQuestion.i);
        writer.l("timestamp");
        this.i.g(writer, remoteQuestion.j);
        writer.l("isDeleted");
        this.j.g(writer, Boolean.valueOf(remoteQuestion.k));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteQuestion)", "toString(...)");
    }
}
