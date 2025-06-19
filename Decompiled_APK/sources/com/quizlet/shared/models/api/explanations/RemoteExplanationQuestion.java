package com.quizlet.shared.models.api.explanations;

import assistantMode.refactored.a;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.K;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteExplanationQuestion {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] l = {null, null, null, null, null, null, new C5048d(K.a, 0), null, null, null, null};
    public final Long a;
    public final String b;
    public final String c;
    public final String d;
    public final Prompt e;
    public final Integer f;
    public final List g;
    public final String h;
    public final Long i;
    public final Long j;
    public final Boolean k;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteExplanationQuestion$$serializer.INSTANCE;
        }
    }

    @f
    @Metadata
    public static final class Prompt {

        @NotNull
        public static final Companion Companion = new Companion();
        public final String a;
        public final Image b;

        @Metadata
        public static final class Companion {
            @NotNull
            public final KSerializer serializer() {
                return RemoteExplanationQuestion$Prompt$$serializer.INSTANCE;
            }
        }

        @f
        @Metadata
        public static final class Image {

            @NotNull
            public static final Companion Companion = new Companion();
            public final String a;
            public final Integer b;
            public final Integer c;

            @Metadata
            public static final class Companion {
                @NotNull
                public final KSerializer serializer() {
                    return RemoteExplanationQuestion$Prompt$Image$$serializer.INSTANCE;
                }
            }

            public /* synthetic */ Image(int i, String str, Integer num, Integer num2) {
                if (7 != (i & 7)) {
                    AbstractC5047c0.k(i, 7, RemoteExplanationQuestion$Prompt$Image$$serializer.INSTANCE.getDescriptor());
                    throw null;
                }
                this.a = str;
                this.b = num;
                this.c = num2;
            }

            public final boolean equals(Object obj) {
                if (this == obj) {
                    return true;
                }
                if (!(obj instanceof Image)) {
                    return false;
                }
                Image image = (Image) obj;
                return Intrinsics.b(this.a, image.a) && Intrinsics.b(this.b, image.b) && Intrinsics.b(this.c, image.c);
            }

            public final int hashCode() {
                int iHashCode = this.a.hashCode() * 31;
                Integer num = this.b;
                int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
                Integer num2 = this.c;
                return iHashCode2 + (num2 != null ? num2.hashCode() : 0);
            }

            public final String toString() {
                StringBuilder sb = new StringBuilder("Image(srcUrl=");
                sb.append(this.a);
                sb.append(", height=");
                sb.append(this.b);
                sb.append(", width=");
                return a.l(sb, this.c, ")");
            }
        }

        public /* synthetic */ Prompt(int i, String str, Image image) {
            if (3 != (i & 3)) {
                AbstractC5047c0.k(i, 3, RemoteExplanationQuestion$Prompt$$serializer.INSTANCE.getDescriptor());
                throw null;
            }
            this.a = str;
            this.b = image;
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof Prompt)) {
                return false;
            }
            Prompt prompt = (Prompt) obj;
            return Intrinsics.b(this.a, prompt.a) && Intrinsics.b(this.b, prompt.b);
        }

        public final int hashCode() {
            String str = this.a;
            int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
            Image image = this.b;
            return iHashCode + (image != null ? image.hashCode() : 0);
        }

        public final String toString() {
            return "Prompt(text=" + this.a + ", image=" + this.b + ")";
        }
    }

    public /* synthetic */ RemoteExplanationQuestion(int i, Long l2, String str, String str2, String str3, Prompt prompt, Integer num, List list, String str4, Long l3, Long l4, Boolean bool) {
        if (1023 != (i & 1023)) {
            AbstractC5047c0.k(i, 1023, RemoteExplanationQuestion$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = l2;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = prompt;
        this.f = num;
        this.g = list;
        this.h = str4;
        this.i = l3;
        this.j = l4;
        if ((i & 1024) == 0) {
            this.k = null;
        } else {
            this.k = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteExplanationQuestion)) {
            return false;
        }
        RemoteExplanationQuestion remoteExplanationQuestion = (RemoteExplanationQuestion) obj;
        return Intrinsics.b(this.a, remoteExplanationQuestion.a) && Intrinsics.b(this.b, remoteExplanationQuestion.b) && Intrinsics.b(this.c, remoteExplanationQuestion.c) && Intrinsics.b(this.d, remoteExplanationQuestion.d) && Intrinsics.b(this.e, remoteExplanationQuestion.e) && Intrinsics.b(this.f, remoteExplanationQuestion.f) && Intrinsics.b(this.g, remoteExplanationQuestion.g) && Intrinsics.b(this.h, remoteExplanationQuestion.h) && Intrinsics.b(this.i, remoteExplanationQuestion.i) && Intrinsics.b(this.j, remoteExplanationQuestion.j) && Intrinsics.b(this.k, remoteExplanationQuestion.k);
    }

    public final int hashCode() {
        Long l2 = this.a;
        int iHashCode = (l2 == null ? 0 : l2.hashCode()) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iHashCode3 = (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Prompt prompt = this.e;
        int iHashCode5 = (iHashCode4 + (prompt == null ? 0 : prompt.hashCode())) * 31;
        Integer num = this.f;
        int iHashCode6 = (iHashCode5 + (num == null ? 0 : num.hashCode())) * 31;
        List list = this.g;
        int iHashCode7 = (iHashCode6 + (list == null ? 0 : list.hashCode())) * 31;
        String str4 = this.h;
        int iHashCode8 = (iHashCode7 + (str4 == null ? 0 : str4.hashCode())) * 31;
        Long l3 = this.i;
        int iHashCode9 = (iHashCode8 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.j;
        int iHashCode10 = (iHashCode9 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Boolean bool = this.k;
        return iHashCode10 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteExplanationQuestion(id=");
        sb.append(this.a);
        sb.append(", questionUuid=");
        sb.append(this.b);
        sb.append(", slug=");
        sb.append(this.c);
        sb.append(", mediaExerciseId=");
        sb.append(this.d);
        sb.append(", prompt=");
        sb.append(this.e);
        sb.append(", answersCount=");
        sb.append(this.f);
        sb.append(", subjectIds=");
        sb.append(this.g);
        sb.append(", webUrl=");
        sb.append(this.h);
        sb.append(", timestamp=");
        sb.append(this.i);
        sb.append(", lastModified=");
        sb.append(this.j);
        sb.append(", isDeleted=");
        return a.k(sb, this.k, ")");
    }
}
