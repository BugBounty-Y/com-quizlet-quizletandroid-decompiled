package com.quizlet.remote.model.search;

import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
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
public final class RemoteSearchSocialSignalForSetsJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;
    public final l d;
    public final l e;
    public final l f;
    public final l g;

    public RemoteSearchSocialSignalForSetsJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("numStudiers", "time", "timeUnit", "largeTimeRange", DBGroupFields.Names.SCHOOL_ID, "schoolName", "studiableId");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "numStudiers");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "timeUnit");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
        l lVarA3 = moshi.a(Boolean.TYPE, m, "largeTimeRange");
        Intrinsics.checkNotNullExpressionValue(lVarA3, "adapter(...)");
        this.d = lVarA3;
        l lVarA4 = moshi.a(Long.class, m, DBGroupFields.Names.SCHOOL_ID);
        Intrinsics.checkNotNullExpressionValue(lVarA4, "adapter(...)");
        this.e = lVarA4;
        l lVarA5 = moshi.a(String.class, m, "schoolName");
        Intrinsics.checkNotNullExpressionValue(lVarA5, "adapter(...)");
        this.f = lVarA5;
        l lVarA6 = moshi.a(Long.TYPE, m, "studiableId");
        Intrinsics.checkNotNullExpressionValue(lVarA6, "adapter(...)");
        this.g = lVarA6;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        Integer num2 = null;
        Boolean bool = null;
        Long l = null;
        String str = null;
        Long l2 = null;
        String str2 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            l lVar = this.b;
            switch (iK0) {
                case -1:
                    reader.m0();
                    reader.n0();
                    break;
                case 0:
                    num = (Integer) lVar.a(reader);
                    if (num == null) {
                        throw com.squareup.moshi.internal.b.k("numStudiers", "numStudiers", reader);
                    }
                    break;
                case 1:
                    num2 = (Integer) lVar.a(reader);
                    if (num2 == null) {
                        throw com.squareup.moshi.internal.b.k("time", "time", reader);
                    }
                    break;
                case 2:
                    str = (String) this.c.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("timeUnit", "timeUnit", reader);
                    }
                    break;
                case 3:
                    bool = (Boolean) this.d.a(reader);
                    if (bool == null) {
                        throw com.squareup.moshi.internal.b.k("largeTimeRange", "largeTimeRange", reader);
                    }
                    break;
                case 4:
                    l2 = (Long) this.e.a(reader);
                    break;
                case 5:
                    str2 = (String) this.f.a(reader);
                    break;
                case 6:
                    l = (Long) this.g.a(reader);
                    if (l == null) {
                        throw com.squareup.moshi.internal.b.k("studiableId", "studiableId", reader);
                    }
                    break;
            }
        }
        reader.i();
        Boolean bool2 = bool;
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("numStudiers", "numStudiers", reader);
        }
        int iIntValue = num.intValue();
        if (num2 == null) {
            throw com.squareup.moshi.internal.b.e("time", "time", reader);
        }
        int iIntValue2 = num2.intValue();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("timeUnit", "timeUnit", reader);
        }
        if (bool2 == null) {
            throw com.squareup.moshi.internal.b.e("largeTimeRange", "largeTimeRange", reader);
        }
        boolean zBooleanValue = bool2.booleanValue();
        if (l != null) {
            return new RemoteSearchSocialSignalForSets(iIntValue, iIntValue2, str, zBooleanValue, l2, str2, l.longValue());
        }
        throw com.squareup.moshi.internal.b.e("studiableId", "studiableId", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSearchSocialSignalForSets remoteSearchSocialSignalForSets = (RemoteSearchSocialSignalForSets) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSearchSocialSignalForSets == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("numStudiers");
        Integer numValueOf = Integer.valueOf(remoteSearchSocialSignalForSets.a);
        l lVar = this.b;
        lVar.g(writer, numValueOf);
        writer.l("time");
        AbstractC4178x.p(remoteSearchSocialSignalForSets.b, lVar, writer, "timeUnit");
        this.c.g(writer, remoteSearchSocialSignalForSets.c);
        writer.l("largeTimeRange");
        this.d.g(writer, Boolean.valueOf(remoteSearchSocialSignalForSets.d));
        writer.l(DBGroupFields.Names.SCHOOL_ID);
        this.e.g(writer, remoteSearchSocialSignalForSets.e);
        writer.l("schoolName");
        this.f.g(writer, remoteSearchSocialSignalForSets.f);
        writer.l("studiableId");
        this.g.g(writer, Long.valueOf(remoteSearchSocialSignalForSets.g));
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(53, "GeneratedJsonAdapter(RemoteSearchSocialSignalForSets)", "toString(...)");
    }
}
