package com.quizlet.remote.model.course;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteDeleteCourseMembershipJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteDeleteCourseMembershipJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("courseId", "userId");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(Long.TYPE, M.a, "courseId");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Long l = null;
        Long l2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    l = (Long) lVar.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("courseId", "courseId", reader);
                    }
                } else if (iK0 == 1 && (l2 = (Long) lVar.a(reader)) == null) {
                    throw com.squareup.moshi.internal.b.k("userId", "userId", reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (l == null) {
            throw com.squareup.moshi.internal.b.e("courseId", "courseId", reader);
        }
        long jLongValue = l.longValue();
        if (l2 != null) {
            return new RemoteDeleteCourseMembership(jLongValue, l2.longValue());
        }
        throw com.squareup.moshi.internal.b.e("userId", "userId", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteDeleteCourseMembership remoteDeleteCourseMembership = (RemoteDeleteCourseMembership) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteDeleteCourseMembership == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("courseId");
        Long lValueOf = Long.valueOf(remoteDeleteCourseMembership.a);
        l lVar = this.b;
        lVar.g(writer, lValueOf);
        writer.l("userId");
        lVar.g(writer, Long.valueOf(remoteDeleteCourseMembership.b));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(50, "GeneratedJsonAdapter(RemoteDeleteCourseMembership)", "toString(...)");
    }
}
