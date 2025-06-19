package com.quizlet.remote.model.practicetests;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.H;
import com.squareup.moshi.l;
import com.squareup.moshi.p;
import com.squareup.moshi.w;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RemoteCreatedPracticeTestModelJsonAdapter extends l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final l b;

    public RemoteCreatedPracticeTestModelJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("practiceTest");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        l lVarA = moshi.a(H.f(List.class, RemoteCreatedPracticeTestUuid.class), M.a, "practiceTest");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        List list = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0 && (list = (List) this.b.a(reader)) == null) {
                throw com.squareup.moshi.internal.b.k("practiceTest", "practiceTest", reader);
            }
        }
        reader.i();
        if (list != null) {
            return new RemoteCreatedPracticeTestModel(list);
        }
        throw com.squareup.moshi.internal.b.e("practiceTest", "practiceTest", reader);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        RemoteCreatedPracticeTestModel remoteCreatedPracticeTestModel = (RemoteCreatedPracticeTestModel) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (remoteCreatedPracticeTestModel == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("practiceTest");
        this.b.g(writer, remoteCreatedPracticeTestModel.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(52, "GeneratedJsonAdapter(RemoteCreatedPracticeTestModel)", "toString(...)");
    }
}
