package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.j2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0665j2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ DialogC0671k2 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0665j2(DialogC0671k2 dialogC0671k2, int i) {
        super(1);
        this.a = i;
        this.b = dialogC0671k2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                DialogC0671k2 dialogC0671k2 = this.b;
                dialogC0671k2.e.getClass();
                dialogC0671k2.d.invoke();
                return Unit.a;
            default:
                DialogC0671k2 dialogC0671k22 = this.b;
                dialogC0671k22.show();
                return new androidx.activity.compose.c(dialogC0671k22, 8);
        }
    }
}
