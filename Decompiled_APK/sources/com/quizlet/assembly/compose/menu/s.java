package com.quizlet.assembly.compose.menu;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class s {
    public final InterfaceC0773a0 a;
    public final InterfaceC0773a0 b;
    public final InterfaceC0773a0 c;

    public s(InterfaceC0773a0 items, InterfaceC0773a0 isFixedItemSize, InterfaceC0773a0 uiState) {
        Intrinsics.checkNotNullParameter(items, "items");
        Intrinsics.checkNotNullParameter(isFixedItemSize, "isFixedItemSize");
        Intrinsics.checkNotNullParameter(uiState, "uiState");
        this.a = items;
        this.b = isFixedItemSize;
        this.c = uiState;
    }

    public final void a() {
        L0 l0 = (L0) this.c;
        if (l0.getValue() != u.b) {
            l0.setValue(u.c);
        }
    }

    public final void b() {
        List items = (List) ((L0) this.a).getValue();
        boolean zBooleanValue = ((Boolean) ((L0) this.b).getValue()).booleanValue();
        Intrinsics.checkNotNullParameter(items, "items");
        c(items, zBooleanValue);
        ((L0) this.c).setValue(u.a);
    }

    public final void c(List items, boolean z) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a.setValue(items);
        this.b.setValue(Boolean.valueOf(z));
    }
}
