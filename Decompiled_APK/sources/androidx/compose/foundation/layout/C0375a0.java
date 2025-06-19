package androidx.compose.foundation.layout;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.layout.a0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0375a0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.runtime.collection.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0375a0(int i, androidx.compose.runtime.collection.b bVar) {
        super(1);
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.runtime.collection.b bVar = this.b;
                int i = bVar.c;
                if (i > 0) {
                    Object[] objArr = bVar.a;
                    int i2 = 0;
                    do {
                        ((androidx.compose.ui.layout.L) objArr[i2]).d();
                        i2++;
                    } while (i2 < i);
                }
                return Unit.a;
            default:
                this.b.b((androidx.compose.ui.o) obj);
                return Boolean.TRUE;
        }
    }
}
