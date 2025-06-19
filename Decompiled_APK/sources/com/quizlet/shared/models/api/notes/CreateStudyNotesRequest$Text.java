package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class CreateStudyNotesRequest$Text implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final boolean b;
    public final String c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return CreateStudyNotesRequest$Text$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ CreateStudyNotesRequest$Text(String str, int i, String str2, boolean z) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, CreateStudyNotesRequest$Text$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = z;
        this.c = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof CreateStudyNotesRequest$Text)) {
            return false;
        }
        CreateStudyNotesRequest$Text createStudyNotesRequest$Text = (CreateStudyNotesRequest$Text) obj;
        return Intrinsics.b(this.a, createStudyNotesRequest$Text.a) && this.b == createStudyNotesRequest$Text.b && Intrinsics.b(this.c, createStudyNotesRequest$Text.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Text(text=");
        sb.append(this.a);
        sb.append(", isPrivate=");
        sb.append(this.b);
        sb.append(", inputType=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }

    public CreateStudyNotesRequest$Text(String text, String inputType, boolean z) {
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(inputType, "inputType");
        this.a = text;
        this.b = z;
        this.c = inputType;
    }
}
