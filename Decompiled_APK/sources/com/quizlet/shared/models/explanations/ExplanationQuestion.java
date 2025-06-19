package com.quizlet.shared.models.explanations;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.a;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class ExplanationQuestion extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] k = {null, null, null, null, null, null, new C5048d(a.f, 0), null, null};
    public final long b;
    public final String c;
    public final String d;
    public final String e;
    public final Prompt f;
    public final Integer g;
    public final List h;
    public final String i;
    public final Boolean j;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ExplanationQuestion$$serializer.INSTANCE;
        }
    }

    @f
    @Metadata
    public static final class Prompt extends e {

        @NotNull
        public static final Companion Companion = new Companion();
        public final String b;
        public final Image c;

        @Metadata
        public static final class Companion {
            @NotNull
            public final KSerializer serializer() {
                return ExplanationQuestion$Prompt$$serializer.INSTANCE;
            }
        }

        @f
        @Metadata
        public static final class Image extends e {

            @NotNull
            public static final Companion Companion = new Companion();
            public final String b;
            public final Integer c;
            public final Integer d;

            @Metadata
            public static final class Companion {
                @NotNull
                public final KSerializer serializer() {
                    return ExplanationQuestion$Prompt$Image$$serializer.INSTANCE;
                }
            }

            public /* synthetic */ Image(int i, String str, Integer num, Integer num2) {
                if (7 != (i & 7)) {
                    AbstractC5047c0.k(i, 7, ExplanationQuestion$Prompt$Image$$serializer.INSTANCE.getDescriptor());
                    throw null;
                }
                this.b = str;
                this.c = num;
                this.d = num2;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Image)) {
                    return false;
                }
                Image image = (Image) obj;
                return Intrinsics.b(this.b, image.b) && Intrinsics.b(this.c, image.c) && Intrinsics.b(this.d, image.d);
            }

            public final int hashCode() {
                int iHashCode = this.b.hashCode() * 31;
                Integer num = this.c;
                int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
                Integer num2 = this.d;
                return iHashCode2 + (num2 != null ? num2.hashCode() : 0);
            }

            public final String toString() {
                StringBuilder sb = new StringBuilder("Image(srcUrl=");
                sb.append(this.b);
                sb.append(", height=");
                sb.append(this.c);
                sb.append(", width=");
                return assistantMode.refactored.a.l(sb, this.d, ")");
            }
        }

        public /* synthetic */ Prompt(int i, String str, Image image) {
            if (3 != (i & 3)) {
                AbstractC5047c0.k(i, 3, ExplanationQuestion$Prompt$$serializer.INSTANCE.getDescriptor());
                throw null;
            }
            this.b = str;
            this.c = image;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Prompt)) {
                return false;
            }
            Prompt prompt = (Prompt) obj;
            return Intrinsics.b(this.b, prompt.b) && Intrinsics.b(this.c, prompt.c);
        }

        public final int hashCode() {
            String str = this.b;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Image image = this.c;
            return iHashCode + (image != null ? image.hashCode() : 0);
        }

        public final String toString() {
            return "Prompt(text=" + this.b + ", image=" + this.c + ")";
        }
    }

    public /* synthetic */ ExplanationQuestion(int i, long j, String str, String str2, String str3, Prompt prompt, Integer num, List list, String str4, Boolean bool) {
        if (255 != (i & 255)) {
            AbstractC5047c0.k(i, 255, ExplanationQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = prompt;
        this.g = num;
        this.h = list;
        this.i = str4;
        if ((i & 256) == 0) {
            this.j = null;
        } else {
            this.j = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExplanationQuestion)) {
            return false;
        }
        ExplanationQuestion explanationQuestion = (ExplanationQuestion) obj;
        return this.b == explanationQuestion.b && Intrinsics.b(this.c, explanationQuestion.c) && Intrinsics.b(this.d, explanationQuestion.d) && Intrinsics.b(this.e, explanationQuestion.e) && Intrinsics.b(this.f, explanationQuestion.f) && Intrinsics.b(this.g, explanationQuestion.g) && Intrinsics.b(this.h, explanationQuestion.h) && Intrinsics.b(this.i, explanationQuestion.i) && Intrinsics.b(this.j, explanationQuestion.j);
    }

    public final int hashCode() {
        int iHashCode = (this.f.hashCode() + d0.e(d0.e(d0.e(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e)) * 31;
        Integer num = this.g;
        int iF = d0.f((iHashCode + (num == null ? 0 : num.hashCode())) * 31, 31, this.h);
        String str = this.i;
        int iHashCode2 = (iF + (str == null ? 0 : str.hashCode())) * 31;
        Boolean bool = this.j;
        return iHashCode2 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExplanationQuestion(id=");
        sb.append(this.b);
        sb.append(", questionUuid=");
        sb.append(this.c);
        sb.append(", slug=");
        sb.append(this.d);
        sb.append(", mediaExerciseId=");
        sb.append(this.e);
        sb.append(", prompt=");
        sb.append(this.f);
        sb.append(", answersCount=");
        sb.append(this.g);
        sb.append(", subjects=");
        sb.append(this.h);
        sb.append(", webUrl=");
        sb.append(this.i);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.j, ")");
    }
}
