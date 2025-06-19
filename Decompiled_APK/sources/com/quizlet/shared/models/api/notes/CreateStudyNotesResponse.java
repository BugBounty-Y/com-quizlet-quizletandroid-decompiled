package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class CreateStudyNotesResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {null, null, new C5048d(CreateStudyNotesArtifactsResponse$$serializer.INSTANCE, 0), null};
    public final String a;
    public final long b;
    public final List c;
    public final Boolean d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CreateStudyNotesResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CreateStudyNotesResponse(int i, String str, long j, List list, Boolean bool) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, CreateStudyNotesResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = j;
        this.c = list;
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CreateStudyNotesResponse)) {
            return false;
        }
        CreateStudyNotesResponse createStudyNotesResponse = (CreateStudyNotesResponse) obj;
        return Intrinsics.b(this.a, createStudyNotesResponse.a) && this.b == createStudyNotesResponse.b && Intrinsics.b(this.c, createStudyNotesResponse.c) && Intrinsics.b(this.d, createStudyNotesResponse.d);
    }

    public final int hashCode() {
        int iF = d0.f(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        Boolean bool = this.d;
        return iF + (bool == null ? 0 : bool.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CreateStudyNotesResponse(uuid=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", artifacts=");
        sb.append(this.c);
        sb.append(", redirectToWeb=");
        return assistantMode.refactored.a.k(sb, this.d, ")");
    }
}
