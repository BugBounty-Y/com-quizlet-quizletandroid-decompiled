package com.quizlet.remote.model.course.memberships;

import com.airbnb.lottie.parser.moshi.c;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.D;
import com.squareup.moshi.internal.b;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteCourseInstanceJsonAdapter extends l {
    public final c a;
    public final l b;
    public final l c;

    public RemoteCourseInstanceJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        c cVarB = c.b("school", "course");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(RemoteSchool.class, m, "school");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(RemoteCourse.class, m, "course");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        RemoteSchool remoteSchool = null;
        RemoteCourse remoteCourse = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                remoteSchool = (RemoteSchool) this.b.a(reader);
                if (remoteSchool == null) {
                    throw b.k("school", "school", reader);
                }
            } else if (iK0 == 1 && (remoteCourse = (RemoteCourse) this.c.a(reader)) == null) {
                throw b.k("course", "course", reader);
            }
        }
        reader.i();
        if (remoteSchool == null) {
            throw b.e("school", "school", reader);
        }
        if (remoteCourse != null) {
            return new RemoteCourseInstance(remoteSchool, remoteCourse);
        }
        throw b.e("course", "course", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteCourseInstance remoteCourseInstance = (RemoteCourseInstance) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteCourseInstance == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("school");
        this.b.g(writer, remoteCourseInstance.a);
        writer.l("course");
        this.c.g(writer, remoteCourseInstance.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(42, "GeneratedJsonAdapter(RemoteCourseInstance)", "toString(...)");
    }
}
