package com.quizlet.remote.model.qclass;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ClassResponse extends ApiResponse {
    public final ClassModels d;

    public ClassResponse(@InterfaceC4853h(name = "models") ClassModels classModels) {
        this.d = classModels;
    }

    @NotNull
    public final ClassResponse copy(@InterfaceC4853h(name = "models") ClassModels classModels) {
        return new ClassResponse(classModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ClassResponse) && Intrinsics.b(this.d, ((ClassResponse) obj).d);
    }

    public final int hashCode() {
        ClassModels classModels = this.d;
        if (classModels == null) {
            return 0;
        }
        return classModels.hashCode();
    }

    public final String toString() {
        return "ClassResponse(models=" + this.d + ")";
    }
}
