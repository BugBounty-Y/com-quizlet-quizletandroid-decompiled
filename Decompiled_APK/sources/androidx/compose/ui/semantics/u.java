package androidx.compose.ui.semantics;

import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class u {
    public final String a;
    public final Function2 b;
    public boolean c;

    public u(String str, Function2 function2) {
        this.a = str;
        this.b = function2;
    }

    public final void a(v vVar, Object obj) {
        ((k) vVar).b(this, obj);
    }

    public final String toString() {
        return "AccessibilityKey: " + this.a;
    }

    public /* synthetic */ u(String str) {
        this(str, q.m);
    }

    public u(String str, boolean z, Function2 function2) {
        this(str, function2);
        this.c = z;
    }
}
