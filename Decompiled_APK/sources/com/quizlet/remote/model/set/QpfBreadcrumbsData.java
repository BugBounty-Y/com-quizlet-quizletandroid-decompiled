package com.quizlet.remote.model.set;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class QpfBreadcrumbsData {
    public final List a;

    public QpfBreadcrumbsData(@InterfaceC4853h(name = "qpfBreadcrumb") List<RemoteQpfBreadcrumbs> list) {
        this.a = list;
    }

    @NotNull
    public final QpfBreadcrumbsData copy(@InterfaceC4853h(name = "qpfBreadcrumb") List<RemoteQpfBreadcrumbs> list) {
        return new QpfBreadcrumbsData(list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof QpfBreadcrumbsData) && Intrinsics.b(this.a, ((QpfBreadcrumbsData) obj).a);
    }

    public final int hashCode() {
        List list = this.a;
        if (list == null) {
            return 0;
        }
        return list.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("QpfBreadcrumbsData(qpfBreadcrumb="), this.a);
    }
}
