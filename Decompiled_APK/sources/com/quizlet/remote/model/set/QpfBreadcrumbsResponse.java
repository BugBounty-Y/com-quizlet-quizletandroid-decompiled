package com.quizlet.remote.model.set;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QpfBreadcrumbsResponse extends ApiResponse {
    public final QpfBreadcrumbsData d;

    public QpfBreadcrumbsResponse(@InterfaceC4853h(name = "data") QpfBreadcrumbsData qpfBreadcrumbsData) {
        this.d = qpfBreadcrumbsData;
    }

    @NotNull
    public final QpfBreadcrumbsResponse copy(@InterfaceC4853h(name = "data") QpfBreadcrumbsData qpfBreadcrumbsData) {
        return new QpfBreadcrumbsResponse(qpfBreadcrumbsData);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QpfBreadcrumbsResponse) && Intrinsics.b(this.d, ((QpfBreadcrumbsResponse) obj).d);
    }

    public final int hashCode() {
        QpfBreadcrumbsData qpfBreadcrumbsData = this.d;
        if (qpfBreadcrumbsData == null) {
            return 0;
        }
        return qpfBreadcrumbsData.hashCode();
    }

    public final String toString() {
        return "QpfBreadcrumbsResponse(data=" + this.d + ")";
    }
}
