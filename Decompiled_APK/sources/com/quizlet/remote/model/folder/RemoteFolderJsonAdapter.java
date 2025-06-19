package com.quizlet.remote.model.folder;

import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.BaseDBModelFields;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.D;
import com.squareup.moshi.w;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolderJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;
    public final com.squareup.moshi.l c;
    public final com.squareup.moshi.l d;
    public final com.squareup.moshi.l e;
    public final com.squareup.moshi.l f;
    public volatile Constructor g;

    public RemoteFolderJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("id", "clientId", "personId", "name", OTUXParamsKeys.OT_UX_DESCRIPTION, "timestamp", "isHidden", "_webUrl", "isDeleted", BaseDBModelFields.Names.CLIENT_TIMESTAMP, "lastModified", "isDirty", DBFolderFields.Names.NUM_SETS, "_numStudyMaterials", DBFolderFields.Names.IS_COURSE_POWERED, "courseName", "schoolName", DBFolderFields.Names.QPF_GENERATION_METHOD);
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        com.squareup.moshi.l lVarA = moshi.a(Long.class, m, "id");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        com.squareup.moshi.l lVarA2 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        com.squareup.moshi.l lVarA3 = moshi.a(Boolean.class, m, "isHidden");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        com.squareup.moshi.l lVarA4 = moshi.a(Boolean.TYPE, m, "isDeleted");
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        com.squareup.moshi.l lVarA5 = moshi.a(Integer.class, m, "numStudyMaterials");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        int i;
        Intrinsics.checkNotNullParameter(reader, "reader");
        Boolean bool = Boolean.FALSE;
        reader.d();
        int i2 = -1;
        Boolean bool2 = bool;
        Boolean bool3 = bool2;
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        Long l4 = null;
        Long l5 = null;
        String str = null;
        String str2 = null;
        Long l6 = null;
        Boolean bool4 = null;
        String str3 = null;
        Long l7 = null;
        Integer num = null;
        Boolean bool5 = null;
        String str4 = null;
        String str5 = null;
        Integer num2 = null;
        while (reader.l()) {
            switch (reader.k0(this.a)) {
                case -1:
                    reader.m0();
                    reader.n0();
                    continue;
                case 0:
                    l3 = (Long) this.b.a(reader);
                    continue;
                case 1:
                    l4 = (Long) this.b.a(reader);
                    continue;
                case 2:
                    l5 = (Long) this.b.a(reader);
                    continue;
                case 3:
                    str = (String) this.c.a(reader);
                    continue;
                case 4:
                    str2 = (String) this.c.a(reader);
                    continue;
                case 5:
                    l6 = (Long) this.b.a(reader);
                    continue;
                case 6:
                    bool4 = (Boolean) this.d.a(reader);
                    continue;
                case 7:
                    str3 = (String) this.c.a(reader);
                    continue;
                case 8:
                    bool2 = (Boolean) this.e.a(reader);
                    if (bool2 == null) {
                        throw com.squareup.moshi.internal.b.k("isDeleted", "isDeleted", reader);
                    }
                    i2 &= -257;
                    continue;
                case 9:
                    l = (Long) this.b.a(reader);
                    continue;
                case 10:
                    l2 = (Long) this.b.a(reader);
                    continue;
                case 11:
                    bool3 = (Boolean) this.e.a(reader);
                    if (bool3 == null) {
                        throw com.squareup.moshi.internal.b.k("isDirty", "isDirty", reader);
                    }
                    i2 &= -2049;
                    continue;
                case 12:
                    l7 = (Long) this.b.a(reader);
                    i2 &= -4097;
                    continue;
                case 13:
                    num = (Integer) this.f.a(reader);
                    i2 &= -8193;
                    continue;
                case 14:
                    bool5 = (Boolean) this.d.a(reader);
                    i2 &= -16385;
                    continue;
                case 15:
                    str4 = (String) this.c.a(reader);
                    i = -32769;
                    break;
                case 16:
                    str5 = (String) this.c.a(reader);
                    i = -65537;
                    break;
                case 17:
                    num2 = (Integer) this.f.a(reader);
                    i = -131073;
                    break;
            }
            i2 &= i;
        }
        reader.i();
        if (i2 == -260353) {
            return new RemoteFolder(l3, l4, l5, str, str2, l6, bool4, str3, bool2.booleanValue(), l, l2, bool3.booleanValue(), l7, num, bool5, str4, str5, num2, null, null, 786432, null);
        }
        Constructor declaredConstructor = this.g;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Boolean.TYPE;
            declaredConstructor = RemoteFolder.class.getDeclaredConstructor(Long.class, Long.class, Long.class, String.class, String.class, Long.class, Boolean.class, String.class, cls2, Long.class, Long.class, cls2, Long.class, Integer.class, Boolean.class, String.class, String.class, Integer.class, RemoteCourse.class, RemoteSchool.class, Integer.TYPE, cls);
            this.g = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Object objNewInstance = declaredConstructor.newInstance(l3, l4, l5, str, str2, l6, bool4, str3, bool2, l, l2, bool3, l7, num, bool5, str4, str5, num2, null, null, Integer.valueOf(i2), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteFolder) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteFolder remoteFolder = (RemoteFolder) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteFolder == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("id");
        com.squareup.moshi.l lVar = this.b;
        lVar.g(writer, remoteFolder.a);
        writer.l("clientId");
        lVar.g(writer, remoteFolder.b);
        writer.l("personId");
        lVar.g(writer, remoteFolder.c);
        writer.l("name");
        com.squareup.moshi.l lVar2 = this.c;
        lVar2.g(writer, remoteFolder.d);
        writer.l(OTUXParamsKeys.OT_UX_DESCRIPTION);
        lVar2.g(writer, remoteFolder.e);
        writer.l("timestamp");
        lVar.g(writer, remoteFolder.f);
        writer.l("isHidden");
        com.squareup.moshi.l lVar3 = this.d;
        lVar3.g(writer, remoteFolder.g);
        writer.l("_webUrl");
        lVar2.g(writer, remoteFolder.h);
        writer.l("isDeleted");
        Boolean boolValueOf = Boolean.valueOf(remoteFolder.i);
        com.squareup.moshi.l lVar4 = this.e;
        lVar4.g(writer, boolValueOf);
        writer.l(BaseDBModelFields.Names.CLIENT_TIMESTAMP);
        lVar.g(writer, remoteFolder.j);
        writer.l("lastModified");
        lVar.g(writer, remoteFolder.k);
        writer.l("isDirty");
        Z.q(remoteFolder.l, lVar4, writer, DBFolderFields.Names.NUM_SETS);
        lVar.g(writer, remoteFolder.m);
        writer.l("_numStudyMaterials");
        com.squareup.moshi.l lVar5 = this.f;
        lVar5.g(writer, remoteFolder.n);
        writer.l(DBFolderFields.Names.IS_COURSE_POWERED);
        lVar3.g(writer, remoteFolder.o);
        writer.l("courseName");
        lVar2.g(writer, remoteFolder.p);
        writer.l("schoolName");
        lVar2.g(writer, remoteFolder.q);
        writer.l(DBFolderFields.Names.QPF_GENERATION_METHOD);
        lVar5.g(writer, remoteFolder.r);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(34, "GeneratedJsonAdapter(RemoteFolder)", "toString(...)");
    }
}
