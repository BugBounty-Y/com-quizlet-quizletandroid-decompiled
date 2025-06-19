package com.quizlet.shared.models.api.studyset;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class TermMetadata {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TermMetadata$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TermMetadata(int i, String str, String str2) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = str;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = str2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TermMetadata)) {
            return false;
        }
        TermMetadata termMetadata = (TermMetadata) obj;
        return Intrinsics.b(this.a, termMetadata.a) && Intrinsics.b(this.b, termMetadata.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TermMetadata(word=");
        sb.append(this.a);
        sb.append(", definition=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
