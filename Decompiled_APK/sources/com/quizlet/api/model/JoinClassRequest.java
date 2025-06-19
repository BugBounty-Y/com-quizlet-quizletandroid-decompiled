package com.quizlet.api.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class JoinClassRequest {

    @JsonProperty("data")
    @NotNull
    private final List<JoinClassData> data;

    @JsonCreator
    public JoinClassRequest(@NotNull List<JoinClassData> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.data = data;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ JoinClassRequest copy$default(JoinClassRequest joinClassRequest, List list, int i, Object obj) {
        if ((i & 1) != 0) {
            list = joinClassRequest.data;
        }
        return joinClassRequest.copy(list);
    }

    @NotNull
    public final List<JoinClassData> component1() {
        return this.data;
    }

    @NotNull
    public final JoinClassRequest copy(@NotNull List<JoinClassData> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new JoinClassRequest(data);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof JoinClassRequest) && Intrinsics.b(this.data, ((JoinClassRequest) obj).data);
    }

    @NotNull
    public final List<JoinClassData> getData() {
        return this.data;
    }

    public int hashCode() {
        return this.data.hashCode();
    }

    @NotNull
    public String toString() {
        return "JoinClassRequest(data=" + this.data + ")";
    }
}
