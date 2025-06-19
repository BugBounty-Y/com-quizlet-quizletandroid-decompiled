package com.quizlet.features.notes.upload.navigation;

import java.util.List;
import kotlin.collections.K;

/* loaded from: classes3.dex */
public final class d implements com.quizlet.ui.compose.navigation.b {
    public static final d a = new d();

    @Override // com.quizlet.ui.compose.navigation.b
    public final List a() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final K c() {
        return K.a;
    }

    @Override // com.quizlet.ui.compose.navigation.b
    public final String e() {
        return "pasteText";
    }

    public final boolean equals(Object obj) {
        return this == obj || (obj instanceof d);
    }

    public final int hashCode() {
        return 2122690685;
    }

    public final String toString() {
        return "PasteText";
    }
}
