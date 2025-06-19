package com.quizlet.remote.model.explanations.textbook;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
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
public final class RemoteTextbookJsonAdapter extends l {
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

    public RemoteTextbookJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "isbn", "title", "authors", "imageUrl", "imageThumbnailUrl", "edition", "isPremium", "_hasSolutions", "_webUrl", "timestamp", "verifiedSolutionCount", "tableOfContents", "isDeleted");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "isbn");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "title");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.class, m, "isPremium");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Long.class, m, "timestampSec");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(Integer.TYPE, m, "verifiedSolutionCount");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
        l lVarA7 = moshi.a(H.f(List.class, com.quizlet.remote.model.explanations.toc.a.class), m, "tableOfContentItems");
        Intrinsics.checkNotNullExpressionValue(lVarA7, "adapter(...)");
        this.h = lVarA7;
        l lVarA8 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA8, "adapter(...)");
        this.i = lVarA8;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        Integer num = 0;
        Boolean bool2 = bool;
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        Boolean bool3 = null;
        Boolean bool4 = null;
        String str7 = null;
        Long l2 = null;
        List list = null;
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
                        throw b.k("isbn", "isbn", reader);
                    }
                    break;
                case 2:
                    str2 = (String) this.d.a(reader);
                    break;
                case 3:
                    str3 = (String) this.d.a(reader);
                    break;
                case 4:
                    str4 = (String) this.d.a(reader);
                    break;
                case 5:
                    str5 = (String) this.d.a(reader);
                    break;
                case 6:
                    str6 = (String) this.d.a(reader);
                    break;
                case 7:
                    bool3 = (Boolean) this.e.a(reader);
                    break;
                case 8:
                    bool4 = (Boolean) this.e.a(reader);
                    break;
                case 9:
                    str7 = (String) this.d.a(reader);
                    break;
                case 10:
                    l2 = (Long) this.f.a(reader);
                    i &= -1025;
                    break;
                case 11:
                    num = (Integer) this.g.a(reader);
                    if (num == null) {
                        throw b.k("verifiedSolutionCount", "verifiedSolutionCount", reader);
                    }
                    i &= -2049;
                    break;
                case 12:
                    list = (List) this.h.a(reader);
                    break;
                case 13:
                    bool2 = (Boolean) this.i.a(reader);
                    if (bool2 == null) {
                        throw b.k("isDeleted", "isDeleted", reader);
                    }
                    i &= -8193;
                    break;
            }
        }
        reader.i();
        if (i == -11265) {
            if (l == null) {
                throw b.e("id", "id", reader);
            }
            long jLongValue = l.longValue();
            if (str != null) {
                return new RemoteTextbook(jLongValue, str, str2, str3, str4, str5, str6, bool3, bool4, str7, l2, num.intValue(), list, bool2.booleanValue());
            }
            throw b.e("isbn", "isbn", reader);
        }
        Constructor declaredConstructor = this.j;
        if (declaredConstructor == null) {
            Class cls = b.c;
            Class cls2 = Integer.TYPE;
            declaredConstructor = RemoteTextbook.class.getDeclaredConstructor(Long.TYPE, String.class, String.class, String.class, String.class, String.class, String.class, Boolean.class, Boolean.class, String.class, Long.class, cls2, List.class, Boolean.TYPE, cls2, cls);
            this.j = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw b.e("id", "id", reader);
        }
        if (str == null) {
            throw b.e("isbn", "isbn", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, str, str2, str3, str4, str5, str6, bool3, bool4, str7, l2, num, list, bool2, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteTextbook) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteTextbook remoteTextbook = (RemoteTextbook) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteTextbook == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteTextbook.a));
        writer.l("isbn");
        this.c.g(writer, remoteTextbook.b);
        writer.l("title");
        l lVar = this.d;
        lVar.g(writer, remoteTextbook.c);
        writer.l("authors");
        lVar.g(writer, remoteTextbook.d);
        writer.l("imageUrl");
        lVar.g(writer, remoteTextbook.e);
        writer.l("imageThumbnailUrl");
        lVar.g(writer, remoteTextbook.f);
        writer.l("edition");
        lVar.g(writer, remoteTextbook.g);
        writer.l("isPremium");
        l lVar2 = this.e;
        lVar2.g(writer, remoteTextbook.h);
        writer.l("_hasSolutions");
        lVar2.g(writer, remoteTextbook.i);
        writer.l("_webUrl");
        lVar.g(writer, remoteTextbook.j);
        writer.l("timestamp");
        this.f.g(writer, remoteTextbook.k);
        writer.l("verifiedSolutionCount");
        this.g.g(writer, Integer.valueOf(remoteTextbook.l));
        writer.l("tableOfContents");
        this.h.g(writer, remoteTextbook.m);
        writer.l("isDeleted");
        this.i.g(writer, Boolean.valueOf(remoteTextbook.n));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(36, "GeneratedJsonAdapter(RemoteTextbook)", "toString(...)");
    }
}
