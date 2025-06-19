package com.quizlet.remote.model.term;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.collections.Z;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteTermJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public volatile Constructor h;

    public RemoteTermJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "setId", "rank", "word", "definition", "_imageUrl", "clientId", DBTermFields.Names.WORD_RICH_TEXT, DBTermFields.Names.DEFINITION_RICH_TEXT, "_wordAudioUrl", "_definitionAudioUrl");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Integer.TYPE, m, "rank");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "word");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "definition");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Long.class, m, "localId");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(String.class, Z.b(new com.quizlet.remote.model.studiableitem.b(1)), DBTermFields.Names.WORD_RICH_TEXT);
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        Long l = null;
        Long l2 = null;
        Integer num = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        Long l3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
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
                    l2 = (Long) this.b.a(reader);
                    if (l2 == null) {
                        throw com.squareup.moshi.internal.b.k("setId", "setId", reader);
                    }
                    break;
                case 2:
                    num = (Integer) this.c.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("rank", "rank", reader);
                    }
                    break;
                case 3:
                    str = (String) this.d.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("word", "word", reader);
                    }
                    i &= -9;
                    break;
                case 4:
                    str2 = (String) this.e.a(reader);
                    break;
                case 5:
                    str3 = (String) this.e.a(reader);
                    break;
                case 6:
                    l3 = (Long) this.f.a(reader);
                    break;
                case 7:
                    str4 = (String) this.g.a(reader);
                    i &= -129;
                    break;
                case 8:
                    str5 = (String) this.g.a(reader);
                    i &= -257;
                    break;
                case 9:
                    str6 = (String) this.e.a(reader);
                    break;
                case 10:
                    str7 = (String) this.e.a(reader);
                    break;
            }
        }
        reader.i();
        if (i == -393) {
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("id", "id", reader);
            }
            long jLongValue = l.longValue();
            if (l2 == null) {
                throw com.squareup.moshi.internal.b.e("setId", "setId", reader);
            }
            long jLongValue2 = l2.longValue();
            if (num == null) {
                throw com.squareup.moshi.internal.b.e("rank", "rank", reader);
            }
            int iIntValue = num.intValue();
            Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
            return new RemoteTerm(jLongValue, jLongValue2, iIntValue, str, str2, str3, l3, str4, str5, str6, str7);
        }
        Constructor declaredConstructor = this.h;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Long.TYPE;
            Class cls3 = Integer.TYPE;
            declaredConstructor = RemoteTerm.class.getDeclaredConstructor(cls2, cls2, cls3, String.class, String.class, String.class, Long.class, String.class, String.class, String.class, String.class, cls3, cls);
            this.h = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("id", "id", reader);
        }
        if (l2 == null) {
            throw com.squareup.moshi.internal.b.e("setId", "setId", reader);
        }
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("rank", "rank", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, l2, num, str, str2, str3, l3, str4, str5, str6, str7, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteTerm) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteTerm remoteTerm = (RemoteTerm) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteTerm == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        Long lValueOf = Long.valueOf(remoteTerm.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("setId");
        com.google.android.gms.measurement.internal.Z.k(remoteTerm.b, lVar, writer, "rank");
        this.c.g(writer, Integer.valueOf(remoteTerm.c));
        writer.l("word");
        this.d.g(writer, remoteTerm.d);
        writer.l("definition");
        l lVar2 = this.e;
        lVar2.g(writer, remoteTerm.e);
        writer.l("_imageUrl");
        lVar2.g(writer, remoteTerm.f);
        writer.l("clientId");
        this.f.g(writer, remoteTerm.g);
        writer.l(DBTermFields.Names.WORD_RICH_TEXT);
        l lVar3 = this.g;
        lVar3.g(writer, remoteTerm.h);
        writer.l(DBTermFields.Names.DEFINITION_RICH_TEXT);
        lVar3.g(writer, remoteTerm.i);
        writer.l("_wordAudioUrl");
        lVar2.g(writer, remoteTerm.j);
        writer.l("_definitionAudioUrl");
        lVar2.g(writer, remoteTerm.k);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(32, "GeneratedJsonAdapter(RemoteTerm)", "toString(...)");
    }
}
