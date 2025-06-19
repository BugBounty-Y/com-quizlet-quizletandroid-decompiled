package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.h0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4285h0 implements InterfaceC4289j0 {
    public final com.quizlet.features.infra.models.share.a a;

    public C4285h0(com.quizlet.features.infra.models.share.a shareRequestData) {
        Intrinsics.checkNotNullParameter(shareRequestData, "shareRequestData");
        this.a = shareRequestData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4285h0) && Intrinsics.b(this.a, ((C4285h0) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ShareFolder(shareRequestData=" + this.a + ")";
    }
}
