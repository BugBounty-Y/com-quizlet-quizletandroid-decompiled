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
public final class StudyNotesResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] j = {null, null, null, null, null, null, null, new C5048d(StudyNotesArtifactsResponse$$serializer.INSTANCE, 0), null};
    public final String a;
    public final long b;
    public final String c;
    public final boolean d;
    public final String e;
    public final String f;
    public final String g;
    public final List h;
    public final Boolean i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNotesResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNotesResponse(int i, String str, long j2, String str2, boolean z, String str3, String str4, String str5, List list, Boolean bool) {
        if (255 != (i & 255)) {
            AbstractC5047c0.k(i, 255, StudyNotesResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = j2;
        this.c = str2;
        this.d = z;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = list;
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNotesResponse)) {
            return false;
        }
        StudyNotesResponse studyNotesResponse = (StudyNotesResponse) obj;
        return Intrinsics.b(this.a, studyNotesResponse.a) && this.b == studyNotesResponse.b && Intrinsics.b(this.c, studyNotesResponse.c) && this.d == studyNotesResponse.d && Intrinsics.b(this.e, studyNotesResponse.e) && Intrinsics.b(this.f, studyNotesResponse.f) && Intrinsics.b(this.g, studyNotesResponse.g) && Intrinsics.b(this.h, studyNotesResponse.h) && Intrinsics.b(this.i, studyNotesResponse.i);
    }

    public final int hashCode() {
        int iG = d0.g(d0.e(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
        String str = this.e;
        int iE = d0.e((iG + (str == null ? 0 : str.hashCode())) * 31, 31, this.f);
        String str2 = this.g;
        int iF = d0.f((iE + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.h);
        Boolean bool = this.i;
        return iF + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyNotesResponse(uuid=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", documentType=");
        sb.append(this.c);
        sb.append(", isPrivate=");
        sb.append(this.d);
        sb.append(", extractedText=");
        sb.append(this.e);
        sb.append(", createdAt=");
        sb.append(this.f);
        sb.append(", userModifiedAt=");
        sb.append(this.g);
        sb.append(", artifacts=");
        sb.append(this.h);
        sb.append(", redirectToWeb=");
        return assistantMode.refactored.a.k(sb, this.i, ")");
    }
}
