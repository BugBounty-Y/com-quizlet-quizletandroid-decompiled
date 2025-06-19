package com.quizlet.remote.model.notes;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class MagicNotesArtifactResponseJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public volatile Constructor f;

    public MagicNotesArtifactResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("uuid", "noteUuid", "userId", "content", DBUserFields.Names.USER_UPGRADE_TYPE, "status", "history");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "uuid");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.TYPE, m, "userId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Integer.TYPE, m, "status");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(String.class, m, "history");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        int i = -1;
        String str = null;
        String str2 = null;
        Long l = null;
        String str3 = null;
        String str4 = null;
        Integer num = null;
        String str5 = null;
        while (reader.l()) {
            String str6 = str;
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    str = (String) this.b.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("uuid", "uuid", reader);
                    }
                    continue;
                case 1:
                    str2 = (String) this.b.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("noteUuid", "noteUuid", reader);
                    }
                    break;
                case 2:
                    l = (Long) this.c.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("userId", "userId", reader);
                    }
                    break;
                case 3:
                    str3 = (String) this.b.a(reader);
                    if (str3 == null) {
                        throw com.squareup.moshi.internal.b.k("content", "content", reader);
                    }
                    break;
                case 4:
                    str4 = (String) this.b.a(reader);
                    if (str4 == null) {
                        throw com.squareup.moshi.internal.b.k(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
                    }
                    break;
                case 5:
                    num = (Integer) this.d.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("status", "status", reader);
                    }
                    break;
                case 6:
                    str5 = (String) this.e.a(reader);
                    str = str6;
                    i = -65;
                    continue;
            }
            str = str6;
        }
        String str7 = str;
        reader.i();
        if (i == -65) {
            if (str7 == null) {
                throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
            }
            if (str2 == null) {
                throw com.squareup.moshi.internal.b.e("noteUuid", "noteUuid", reader);
            }
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
            }
            Integer num2 = num;
            String str8 = str5;
            String str9 = str3;
            String str10 = str4;
            long jLongValue = l.longValue();
            if (str9 == null) {
                throw com.squareup.moshi.internal.b.e("content", "content", reader);
            }
            if (str10 == null) {
                throw com.squareup.moshi.internal.b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
            }
            if (num2 == null) {
                throw com.squareup.moshi.internal.b.e("status", "status", reader);
            }
            return new MagicNotesArtifactResponse(str7, str2, jLongValue, str9, str10, num2.intValue(), str8);
        }
        Integer num3 = num;
        String str11 = str5;
        String str12 = str3;
        String str13 = str4;
        Constructor declaredConstructor = this.f;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Integer.TYPE;
            declaredConstructor = MagicNotesArtifactResponse.class.getDeclaredConstructor(String.class, String.class, Long.TYPE, String.class, String.class, cls2, String.class, cls2, cls);
            this.f = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (str7 == null) {
            throw com.squareup.moshi.internal.b.e("uuid", "uuid", reader);
        }
        if (str2 == null) {
            throw com.squareup.moshi.internal.b.e("noteUuid", "noteUuid", reader);
        }
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
        }
        if (str12 == null) {
            throw com.squareup.moshi.internal.b.e("content", "content", reader);
        }
        if (str13 == null) {
            throw com.squareup.moshi.internal.b.e(DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.USER_UPGRADE_TYPE, reader);
        }
        if (num3 == null) {
            throw com.squareup.moshi.internal.b.e("status", "status", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(str7, str2, l, str12, str13, num3, str11, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (MagicNotesArtifactResponse) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        MagicNotesArtifactResponse magicNotesArtifactResponse = (MagicNotesArtifactResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (magicNotesArtifactResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("uuid");
        l lVar = this.b;
        lVar.g(writer, magicNotesArtifactResponse.a);
        writer.l("noteUuid");
        lVar.g(writer, magicNotesArtifactResponse.b);
        writer.l("userId");
        this.c.g(writer, Long.valueOf(magicNotesArtifactResponse.c));
        writer.l("content");
        lVar.g(writer, magicNotesArtifactResponse.d);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        lVar.g(writer, magicNotesArtifactResponse.e);
        writer.l("status");
        this.d.g(writer, Integer.valueOf(magicNotesArtifactResponse.f));
        writer.l("history");
        this.e.g(writer, magicNotesArtifactResponse.g);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(48, "GeneratedJsonAdapter(MagicNotesArtifactResponse)", "toString(...)");
    }
}
