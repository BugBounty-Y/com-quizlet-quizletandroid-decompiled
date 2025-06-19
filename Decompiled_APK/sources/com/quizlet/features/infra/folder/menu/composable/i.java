package com.quizlet.features.infra.folder.menu.composable;

import androidx.compose.material3.V3;
import com.quizlet.features.infra.folder.menu.data.x;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements V3 {
    public final x a;

    public i(x event) {
        Intrinsics.checkNotNullParameter(event, "event");
        this.a = event;
    }

    @Override // androidx.compose.material3.V3
    public final String a() {
        return "";
    }

    @Override // androidx.compose.material3.V3
    public final String b() {
        return null;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof i) {
            return Intrinsics.b(this.a, ((i) obj).a);
        }
        return false;
    }

    @Override // androidx.compose.material3.V3
    public final int getDuration() {
        return 1;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AddToFolderSnackbarVisuals(event=" + this.a + ", withDismissAction=true)";
    }
}
