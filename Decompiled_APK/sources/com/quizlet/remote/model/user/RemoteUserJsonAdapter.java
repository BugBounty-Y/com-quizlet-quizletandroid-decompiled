package com.quizlet.remote.model.user;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
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
public final class RemoteUserJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;
    public volatile Constructor h;

    public RemoteUserJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("id", "username", "timestamp", "lastModified", DBUserFields.Names.IS_VERIFIED, DBUserFields.Names.USER_UPGRADE_TYPE, DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE, "isLocked", "_imageUrl", DBUserFields.Names.TIME_ZONE, DBUserFields.Names.PROFILE_IMAGE_ID, "isDeleted", "_numCreatedSets", "_numClassMemberships", "_isUnderAge");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "username");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Long.class, m, "timestamp");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Boolean.class, m, DBUserFields.Names.IS_VERIFIED);
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(Integer.class, m, "upgradeType");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i = -1;
        Boolean bool2 = bool;
        Long l = null;
        String str = null;
        String str2 = null;
        String str3 = null;
        Long l2 = null;
        Long l3 = null;
        Boolean bool3 = null;
        Integer num = null;
        Integer num2 = null;
        Boolean bool4 = null;
        String str4 = null;
        Integer num3 = null;
        Integer num4 = null;
        Boolean bool5 = null;
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
                    str3 = (String) this.c.a(reader);
                    break;
                case 2:
                    l2 = (Long) this.d.a(reader);
                    break;
                case 3:
                    l3 = (Long) this.d.a(reader);
                    break;
                case 4:
                    bool3 = (Boolean) this.e.a(reader);
                    i &= -17;
                    break;
                case 5:
                    num = (Integer) this.f.a(reader);
                    break;
                case 6:
                    num2 = (Integer) this.f.a(reader);
                    break;
                case 7:
                    bool4 = (Boolean) this.e.a(reader);
                    break;
                case 8:
                    str4 = (String) this.c.a(reader);
                    break;
                case 9:
                    str = (String) this.c.a(reader);
                    break;
                case 10:
                    str2 = (String) this.c.a(reader);
                    break;
                case 11:
                    bool2 = (Boolean) this.g.a(reader);
                    if (bool2 == null) {
                        throw b.k("isDeleted", "isDeleted", reader);
                    }
                    i &= -2049;
                    break;
                case 12:
                    num3 = (Integer) this.f.a(reader);
                    break;
                case 13:
                    num4 = (Integer) this.f.a(reader);
                    break;
                case 14:
                    bool5 = (Boolean) this.e.a(reader);
                    i &= -16385;
                    break;
            }
        }
        reader.i();
        if (i == -18449) {
            if (l == null) {
                throw b.e("id", "id", reader);
            }
            return new RemoteUser(l.longValue(), str3, l2, l3, bool3, num, num2, bool4, str4, str, str2, bool2.booleanValue(), num3, num4, bool5);
        }
        Constructor declaredConstructor = this.h;
        if (declaredConstructor == null) {
            declaredConstructor = RemoteUser.class.getDeclaredConstructor(Long.TYPE, String.class, Long.class, Long.class, Boolean.class, Integer.class, Integer.class, Boolean.class, String.class, String.class, String.class, Boolean.TYPE, Integer.class, Integer.class, Boolean.class, Integer.TYPE, b.c);
            this.h = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        if (l == null) {
            throw b.e("id", "id", reader);
        }
        Object objNewInstance = declaredConstructor.newInstance(l, str3, l2, l3, bool3, num, num2, bool4, str4, str, str2, bool2, num3, num4, bool5, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteUser) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteUser remoteUser = (RemoteUser) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteUser == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        this.b.g(writer, Long.valueOf(remoteUser.a));
        writer.l("username");
        l lVar = this.c;
        lVar.g(writer, remoteUser.b);
        writer.l("timestamp");
        l lVar2 = this.d;
        lVar2.g(writer, remoteUser.c);
        writer.l("lastModified");
        lVar2.g(writer, remoteUser.d);
        writer.l(DBUserFields.Names.IS_VERIFIED);
        l lVar3 = this.e;
        lVar3.g(writer, remoteUser.e);
        writer.l(DBUserFields.Names.USER_UPGRADE_TYPE);
        l lVar4 = this.f;
        lVar4.g(writer, remoteUser.f);
        writer.l(DBUserFields.Names.SELF_IDENTIFIED_USER_TYPE);
        lVar4.g(writer, remoteUser.g);
        writer.l("isLocked");
        lVar3.g(writer, remoteUser.h);
        writer.l("_imageUrl");
        lVar.g(writer, remoteUser.i);
        writer.l(DBUserFields.Names.TIME_ZONE);
        lVar.g(writer, remoteUser.j);
        writer.l(DBUserFields.Names.PROFILE_IMAGE_ID);
        lVar.g(writer, remoteUser.k);
        writer.l("isDeleted");
        this.g.g(writer, Boolean.valueOf(remoteUser.l));
        writer.l("_numCreatedSets");
        lVar4.g(writer, remoteUser.m);
        writer.l("_numClassMemberships");
        lVar4.g(writer, remoteUser.n);
        writer.l("_isUnderAge");
        lVar3.g(writer, remoteUser.o);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(32, "GeneratedJsonAdapter(RemoteUser)", "toString(...)");
    }
}
