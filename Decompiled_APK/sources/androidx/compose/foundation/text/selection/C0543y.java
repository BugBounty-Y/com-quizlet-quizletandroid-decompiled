package androidx.compose.foundation.text.selection;

import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.text.selection.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C0543y implements InterfaceC0533n, InterfaceC4953l {
    public final /* synthetic */ Function0 a;

    public C0543y(Function0 function0) {
        this.a = function0;
    }

    @Override // androidx.compose.foundation.text.selection.InterfaceC0533n
    public final /* synthetic */ long a() {
        return ((androidx.compose.ui.geometry.b) this.a.invoke()).a;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof InterfaceC0533n) || !(obj instanceof InterfaceC4953l)) {
            return false;
        }
        return Intrinsics.b(this.a, ((InterfaceC4953l) obj).getFunctionDelegate());
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    public final InterfaceC4938g getFunctionDelegate() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
