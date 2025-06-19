package com.quizlet.assembly.compose.modals;

import android.os.Bundle;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class x {
    public final InterfaceC0773a0 a;
    public final boolean b;
    public Bundle c;

    public x(InterfaceC0773a0 visibility, boolean z) {
        Intrinsics.checkNotNullParameter(visibility, "visibility");
        this.a = visibility;
        this.b = z;
    }

    public static void d(x xVar) {
        xVar.c = null;
        ((L0) xVar.a).setValue(y.a);
    }

    public final void a() {
        this.a.setValue(y.c);
        this.c = null;
    }

    public final boolean b() {
        return ((L0) this.a).getValue() == y.a;
    }

    public final void c() {
        this.a.setValue(y.b);
        this.c = null;
    }
}
