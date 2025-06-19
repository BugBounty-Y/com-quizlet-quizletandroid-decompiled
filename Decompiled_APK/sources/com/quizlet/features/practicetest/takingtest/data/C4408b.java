package com.quizlet.features.practicetest.takingtest.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4408b implements InterfaceC4410d {
    public final ArrayList a;

    public C4408b(ArrayList choices) {
        Intrinsics.checkNotNullParameter(choices, "choices");
        this.a = choices;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4408b) && this.a.equals(((C4408b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("MultipleChoiceData(choices="), this.a);
    }
}
