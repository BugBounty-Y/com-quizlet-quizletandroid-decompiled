package com.quizlet.remote.model.selectedterm;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class SelectedTermResponse extends ApiResponse {
    public final SelectedTermModels d;

    public SelectedTermResponse(@InterfaceC4853h(name = "models") SelectedTermModels selectedTermModels) {
        this.d = selectedTermModels;
    }

    @NotNull
    public final SelectedTermResponse copy(@InterfaceC4853h(name = "models") SelectedTermModels selectedTermModels) {
        return new SelectedTermResponse(selectedTermModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof SelectedTermResponse) && Intrinsics.b(this.d, ((SelectedTermResponse) obj).d);
    }

    public final int hashCode() {
        SelectedTermModels selectedTermModels = this.d;
        if (selectedTermModels == null) {
            return 0;
        }
        return selectedTermModels.hashCode();
    }

    public final String toString() {
        return "SelectedTermResponse(models=" + this.d + ")";
    }
}
