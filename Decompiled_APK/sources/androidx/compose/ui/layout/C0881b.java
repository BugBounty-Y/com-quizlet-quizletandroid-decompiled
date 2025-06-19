package androidx.compose.ui.layout;

import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.C4956o;

/* renamed from: androidx.compose.ui.layout.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0881b extends C4956o implements Function2 {
    public static final C0881b a = new C0881b(2, kotlin.math.a.class, "max", "max(II)I", 1);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return Integer.valueOf(Math.max(((Number) obj).intValue(), ((Number) obj2).intValue()));
    }
}
