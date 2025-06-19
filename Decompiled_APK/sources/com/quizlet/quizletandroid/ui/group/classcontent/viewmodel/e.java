package com.quizlet.quizletandroid.ui.group.classcontent.viewmodel;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends h {
    public final ArrayList a;

    public e(ArrayList contentItems) {
        Intrinsics.checkNotNullParameter(contentItems, "contentItems");
        this.a = contentItems;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && this.a.equals(((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("Content(contentItems="), this.a);
    }
}
