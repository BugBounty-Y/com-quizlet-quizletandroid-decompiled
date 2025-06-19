package androidx.compose.foundation.pager;

import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.pager.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0463b extends kotlin.jvm.internal.r implements Function2 {
    public static final C0463b a = new C0463b(2);

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        C0466e c0466e = (C0466e) obj2;
        return kotlin.collections.B.j(Integer.valueOf(c0466e.j()), Float.valueOf(kotlin.ranges.l.b(c0466e.c.j(), -0.5f, 0.5f)), Integer.valueOf(c0466e.l()));
    }
}
