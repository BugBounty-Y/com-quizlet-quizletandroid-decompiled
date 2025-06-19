package androidx.navigation;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1290l {
    public final C1288j a = new C1288j();
    public Object b;

    public final void a(Object obj) {
        this.b = obj;
        C1288j c1288j = this.a;
        c1288j.e = obj;
        c1288j.b = true;
    }

    public final void b(S type) {
        Intrinsics.checkNotNullParameter(type, "value");
        C1288j c1288j = this.a;
        Intrinsics.checkNotNullParameter(type, "type");
        c1288j.d = type;
    }
}
