package androidx.compose.material3;

import java.util.Collection;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes.dex */
public final class U0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ IntRange a;
    public final /* synthetic */ androidx.compose.foundation.lazy.grid.A b;
    public final /* synthetic */ kotlinx.coroutines.C c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;
    public final /* synthetic */ int f;
    public final /* synthetic */ int g;
    public final /* synthetic */ Function1 h;
    public final /* synthetic */ InterfaceC0764y3 i;
    public final /* synthetic */ C0699p0 j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U0(IntRange intRange, androidx.compose.foundation.lazy.grid.A a, kotlinx.coroutines.C c, String str, String str2, int i, int i2, Function1 function1, InterfaceC0764y3 interfaceC0764y3, C0699p0 c0699p0) {
        super(1);
        this.a = intRange;
        this.b = a;
        this.c = c;
        this.d = str;
        this.e = str2;
        this.f = i;
        this.g = i2;
        this.h = function1;
        this.i = interfaceC0764y3;
        this.j = c0699p0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        int size;
        androidx.compose.foundation.lazy.grid.i iVar = (androidx.compose.foundation.lazy.grid.i) obj;
        Iterable iterable = this.a;
        Intrinsics.checkNotNullParameter(iterable, "<this>");
        if (iterable instanceof Collection) {
            size = ((Collection) iterable).size();
        } else {
            kotlin.ranges.i it2 = iterable.iterator();
            size = 0;
            while (it2.c) {
                it2.next();
                size++;
                if (size < 0) {
                    kotlin.collections.B.o();
                    throw null;
                }
            }
        }
        androidx.compose.foundation.lazy.grid.i.q(iVar, size, null, null, new androidx.compose.runtime.internal.d(true, 1040623618, new T0(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j)), 14);
        return Unit.a;
    }
}
