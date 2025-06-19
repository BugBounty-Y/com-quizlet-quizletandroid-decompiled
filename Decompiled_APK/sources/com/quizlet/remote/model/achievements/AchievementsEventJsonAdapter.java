package com.quizlet.remote.model.achievements;

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
public final class AchievementsEventJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;
    public final l c;

    public AchievementsEventJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("target", "action", "targetId");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        M m = M.a;
        l lVarA = moshi.a(String.class, m, "target");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
        l lVarA2 = moshi.a(String.class, m, "targetId");
        Intrinsics.checkNotNullExpressionValue(lVarA2, "adapter(...)");
        this.c = lVarA2;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        String str = null;
        String str2 = null;
        String str3 = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 != -1) {
                l lVar = this.b;
                if (iK0 == 0) {
                    str = (String) lVar.a(reader);
                    if (str == null) {
                        throw com.squareup.moshi.internal.b.k("target", "target", reader);
                    }
                } else if (iK0 == 1) {
                    str2 = (String) lVar.a(reader);
                    if (str2 == null) {
                        throw com.squareup.moshi.internal.b.k("action", "action", reader);
                    }
                } else if (iK0 == 2) {
                    str3 = (String) this.c.a(reader);
                }
            } else {
                reader.m0();
                reader.n0();
            }
        }
        reader.i();
        if (str == null) {
            throw com.squareup.moshi.internal.b.e("target", "target", reader);
        }
        if (str2 != null) {
            return new AchievementsEvent(str, str2, str3);
        }
        throw com.squareup.moshi.internal.b.e("action", "action", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        AchievementsEvent achievementsEvent = (AchievementsEvent) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (achievementsEvent == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("target");
        l lVar = this.b;
        lVar.g(writer, achievementsEvent.a);
        writer.l("action");
        lVar.g(writer, achievementsEvent.b);
        writer.l("targetId");
        this.c.g(writer, achievementsEvent.c);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(39, "GeneratedJsonAdapter(AchievementsEvent)", "toString(...)");
    }
}
