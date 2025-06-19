package androidx.compose.ui.graphics;

import android.graphics.Canvas;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.graphics.e, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0845e {
    public static final Canvas a = new Canvas();

    public static final Canvas a(InterfaceC0858s interfaceC0858s) {
        Intrinsics.e(interfaceC0858s, "null cannot be cast to non-null type androidx.compose.ui.graphics.AndroidCanvas");
        return ((C0844d) interfaceC0858s).a;
    }
}
