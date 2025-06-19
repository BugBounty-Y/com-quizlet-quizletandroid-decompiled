package androidx.compose.ui.semantics;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class i {
    public final kotlin.jvm.internal.r a;
    public final kotlin.jvm.internal.r b;

    /* JADX WARN: Multi-variable type inference failed */
    public i(Function0 function0, Function0 function02) {
        this.a = (kotlin.jvm.internal.r) function0;
        this.b = (kotlin.jvm.internal.r) function02;
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public final Function0 a() {
        return this.b;
    }

    /* JADX WARN: Type inference failed for: r1v1, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    /* JADX WARN: Type inference failed for: r1v6, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.r] */
    public final String toString() {
        return "ScrollAxisRange(value=" + ((Number) this.a.invoke()).floatValue() + ", maxValue=" + ((Number) this.b.invoke()).floatValue() + ", reverseScrolling=false)";
    }
}
