package com.quizlet.remote.model.course;

import com.google.android.gms.measurement.internal.Z;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
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
public final class RemoteNewCourseMembershipJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public volatile Constructor e;

    public RemoteNewCourseMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("courseId", DBGroupFields.Names.SCHOOL_ID, "userId", "folderName");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Long.TYPE, m, "courseId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(Long.class, m, DBGroupFields.Names.SCHOOL_ID);
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(String.class, m, "folderName");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) throws IllegalAccessException, NoSuchMethodException, InstantiationException, SecurityException, IllegalArgumentException, InvocationTargetException {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        Long l3 = null;
        String str = null;
        int i = -1;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                l = (Long) this.b.a(reader);
                if (l == null) {
                    throw com.squareup.moshi.internal.b.k("courseId", "courseId", reader);
                }
            } else if (iK0 == 1) {
                l2 = (Long) this.c.a(reader);
            } else if (iK0 == 2) {
                l3 = (Long) this.b.a(reader);
                if (l3 == null) {
                    throw com.squareup.moshi.internal.b.k("userId", "userId", reader);
                }
            } else if (iK0 == 3) {
                str = (String) this.d.a(reader);
                i = -9;
            }
        }
        reader.i();
        if (i == -9) {
            Long l4 = l2;
            if (l == null) {
                throw com.squareup.moshi.internal.b.e("courseId", "courseId", reader);
            }
            Long l5 = l3;
            String str2 = str;
            long jLongValue = l.longValue();
            if (l5 != null) {
                return new RemoteNewCourseMembership(jLongValue, l4, l5.longValue(), str2);
            }
            throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
        }
        Long l6 = l2;
        Long l7 = l3;
        String str3 = str;
        Constructor declaredConstructor = this.e;
        if (declaredConstructor == null) {
            Class cls = com.squareup.moshi.internal.b.c;
            Class cls2 = Long.TYPE;
            declaredConstructor = RemoteNewCourseMembership.class.getDeclaredConstructor(cls2, Long.class, cls2, String.class, Integer.TYPE, cls);
            this.e = declaredConstructor;
            Intrinsics.checkNotNullExpressionValue(declaredConstructor, "also(...)");
        }
        Constructor constructor = declaredConstructor;
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("courseId", "courseId", reader);
        }
        if (l7 == null) {
            throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
        }
        Object objNewInstance = constructor.newInstance(l, l6, l7, str3, Integer.valueOf(i), null);
        Intrinsics.checkNotNullExpressionValue(objNewInstance, "newInstance(...)");
        return (RemoteNewCourseMembership) objNewInstance;
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteNewCourseMembership remoteNewCourseMembership = (RemoteNewCourseMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteNewCourseMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseId");
        Long lValueOf = Long.valueOf(remoteNewCourseMembership.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        this.c.g(writer, remoteNewCourseMembership.b);
        writer.l("userId");
        Z.k(remoteNewCourseMembership.c, lVar, writer, "folderName");
        this.d.g(writer, remoteNewCourseMembership.d);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(47, "GeneratedJsonAdapter(RemoteNewCourseMembership)", "toString(...)");
    }
}
