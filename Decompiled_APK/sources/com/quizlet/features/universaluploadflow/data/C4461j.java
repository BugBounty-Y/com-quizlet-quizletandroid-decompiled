package com.quizlet.features.universaluploadflow.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4461j implements r {
    public final ArrayList a;

    public C4461j(ArrayList uris) {
        Intrinsics.checkNotNullParameter(uris, "uris");
        this.a = uris;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4461j) && this.a.equals(((C4461j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("FilesSelected(uris="), this.a);
    }
}
