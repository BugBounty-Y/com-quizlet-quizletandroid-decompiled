package com.quizlet.shared.models.api.base;

import com.quizlet.shared.models.api.base.errors.QuizletApiError;
import com.quizlet.shared.models.api.base.errors.ValidationError$$serializer;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class QuizletApiThreeResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, null, null, new C5048d(ValidationError$$serializer.INSTANCE, 0), null};
    public final ModelWrapper a;
    public final DataWrapper b;
    public final QuizletApiError c;
    public final List d;
    public final PagingInfo e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return QuizletApiThreeResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ QuizletApiThreeResponse(int i, ModelWrapper modelWrapper, DataWrapper dataWrapper, QuizletApiError quizletApiError, List list, PagingInfo pagingInfo) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = modelWrapper;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = dataWrapper;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = quizletApiError;
        }
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = list;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = pagingInfo;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof QuizletApiThreeResponse)) {
            return false;
        }
        QuizletApiThreeResponse quizletApiThreeResponse = (QuizletApiThreeResponse) obj;
        return Intrinsics.b(this.a, quizletApiThreeResponse.a) && Intrinsics.b(this.b, quizletApiThreeResponse.b) && Intrinsics.b(this.c, quizletApiThreeResponse.c) && Intrinsics.b(this.d, quizletApiThreeResponse.d) && Intrinsics.b(this.e, quizletApiThreeResponse.e);
    }

    public final int hashCode() {
        ModelWrapper modelWrapper = this.a;
        int iHashCode = (modelWrapper == null ? 0 : modelWrapper.hashCode()) * 31;
        DataWrapper dataWrapper = this.b;
        int iHashCode2 = (iHashCode + (dataWrapper == null ? 0 : dataWrapper.hashCode())) * 31;
        QuizletApiError quizletApiError = this.c;
        int iHashCode3 = (iHashCode2 + (quizletApiError == null ? 0 : quizletApiError.hashCode())) * 31;
        List list = this.d;
        int iHashCode4 = (iHashCode3 + (list == null ? 0 : list.hashCode())) * 31;
        PagingInfo pagingInfo = this.e;
        return iHashCode4 + (pagingInfo != null ? pagingInfo.hashCode() : 0);
    }

    public final String toString() {
        return "QuizletApiThreeResponse(models=" + this.a + ", data=" + this.b + ", error=" + this.c + ", validationErrors=" + this.d + ", paging=" + this.e + ")";
    }
}
