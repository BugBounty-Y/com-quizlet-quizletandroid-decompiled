package com.quizlet.features.infra.snackbar.composables;

import androidx.compose.material3.V3;
import com.quizlet.features.infra.snackbar.l;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements V3 {
    public final l a;
    public final int b;

    public a(l data) {
        int i;
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
        int i2 = data.b;
        if (i2 != -2) {
            i = 1;
            if (i2 != -1 && i2 == 0) {
                i = 2;
            }
        } else {
            i = 3;
        }
        this.b = i;
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
        if (obj instanceof a) {
            return Intrinsics.b(this.a, ((a) obj).a);
        }
        return false;
    }

    @Override // androidx.compose.material3.V3
    public final int getDuration() {
        return this.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(true) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MessageFeedbackSnackbarVisuals(data=" + this.a + ", withDismissAction=true)";
    }
}
