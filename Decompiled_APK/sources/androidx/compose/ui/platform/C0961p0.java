package androidx.compose.ui.platform;

import java.util.Map;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.ui.platform.p0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0961p0 implements androidx.compose.runtime.saveable.i {
    public final androidx.compose.foundation.text.L a;
    public final /* synthetic */ androidx.compose.runtime.saveable.j b;

    public C0961p0(androidx.compose.runtime.saveable.j jVar, androidx.compose.foundation.text.L l) {
        this.a = l;
        this.b = jVar;
    }

    @Override // androidx.compose.runtime.saveable.i
    public final boolean a(Object obj) {
        return this.b.a(obj);
    }

    @Override // androidx.compose.runtime.saveable.i
    public final Map b() {
        return this.b.b();
    }

    @Override // androidx.compose.runtime.saveable.i
    public final Object c(String str) {
        return this.b.c(str);
    }

    @Override // androidx.compose.runtime.saveable.i
    public final androidx.compose.runtime.saveable.h d(String str, Function0 function0) {
        return this.b.d(str, function0);
    }
}
