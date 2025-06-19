package com.quizlet.features.notes.detail.menu;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements n {
    public final ArrayList a;

    public m(ArrayList items) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a = items;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && this.a.equals(((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("Open(items="), this.a);
    }
}
