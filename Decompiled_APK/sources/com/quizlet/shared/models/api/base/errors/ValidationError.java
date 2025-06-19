package com.quizlet.shared.models.api.base.errors;

import android.support.v4.media.session.a;
import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class ValidationError {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final String c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ValidationError$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ValidationError(String str, int i, String str2, String str3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, ValidationError$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = str3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ValidationError)) {
            return false;
        }
        ValidationError validationError = (ValidationError) obj;
        return Intrinsics.b(this.a, validationError.a) && Intrinsics.b(this.b, validationError.b) && Intrinsics.b(this.c, validationError.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ValidationError(identifier=");
        sb.append(this.a);
        sb.append(", message=");
        sb.append(this.b);
        sb.append(", field=");
        return a.t(sb, this.c, ")");
    }
}
