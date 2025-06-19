package com.quizlet.remote.model.folder;

import com.quizlet.data.model.AbstractC4178x;
import com.squareup.moshi.D;
import com.squareup.moshi.w;
import kotlin.Metadata;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class FolderCopyEligibilityResponseJsonAdapter extends com.squareup.moshi.l {
    public final com.airbnb.lottie.parser.moshi.c a;
    public final com.squareup.moshi.l b;

    public FolderCopyEligibilityResponseJsonAdapter(@NotNull D moshi) {
        Intrinsics.checkNotNullParameter(moshi, "moshi");
        com.airbnb.lottie.parser.moshi.c cVarB = com.airbnb.lottie.parser.moshi.c.b("isUserEligibleToCopyFolder");
        Intrinsics.checkNotNullExpressionValue(cVarB, "of(...)");
        this.a = cVarB;
        com.squareup.moshi.l lVarA = moshi.a(Boolean.class, M.a, "isUserEligibleToCopyFolder");
        Intrinsics.checkNotNullExpressionValue(lVarA, "adapter(...)");
        this.b = lVarA;
    }

    @Override // com.squareup.moshi.l
    public final Object a(com.squareup.moshi.p reader) {
        Intrinsics.checkNotNullParameter(reader, "reader");
        reader.d();
        Boolean bool = null;
        while (reader.l()) {
            int iK0 = reader.k0(this.a);
            if (iK0 == -1) {
                reader.m0();
                reader.n0();
            } else if (iK0 == 0) {
                bool = (Boolean) this.b.a(reader);
            }
        }
        reader.i();
        return new FolderCopyEligibilityResponse(bool);
    }

    @Override // com.squareup.moshi.l
    public final void g(w writer, Object obj) {
        FolderCopyEligibilityResponse folderCopyEligibilityResponse = (FolderCopyEligibilityResponse) obj;
        Intrinsics.checkNotNullParameter(writer, "writer");
        if (folderCopyEligibilityResponse == null) {
            throw new NullPointerException("value_ was null! Wrap in .nullSafe() to write nullable values.");
        }
        writer.d();
        writer.l("isUserEligibleToCopyFolder");
        this.b.g(writer, folderCopyEligibilityResponse.a);
        writer.f();
    }

    public final String toString() {
        return AbstractC4178x.m(51, "GeneratedJsonAdapter(FolderCopyEligibilityResponse)", "toString(...)");
    }
}
