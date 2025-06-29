package com.quizlet.remote.model.set;

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
public final class RemoteSetLineageJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public RemoteSetLineageJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("level", "name");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(Integer.TYPE, m, "level");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "name");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Integer num = null;
        String str = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                num = (Integer) this.b.a(reader);
                if (num == null) {
                    throw com.squareup.moshi.internal.b.k("level", "level", reader);
                }
            } else if (iK0 == 1 && (str = (String) this.c.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("name", "name", reader);
            }
        }
        reader.i();
        if (num == null) {
            throw com.squareup.moshi.internal.b.e("level", "level", reader);
        }
        int iIntValue = num.intValue();
        if (str != null) {
            return new RemoteSetLineage(iIntValue, str);
        }
        throw com.squareup.moshi.internal.b.e("name", "name", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteSetLineage remoteSetLineage = (RemoteSetLineage) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteSetLineage == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("level");
        this.b.g(writer, Integer.valueOf(remoteSetLineage.a));
        writer.l("name");
        this.c.g(writer, remoteSetLineage.b);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(38, "GeneratedJsonAdapter(RemoteSetLineage)", "toString(...)");
    }
}
