package androidx.compose.ui.viewinterop;

import androidx.compose.ui.text.input.C;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public static final a b = new a(1, 0);
    public static final a c = new a(1, 1);
    public static final a d = new a(1, 2);
    public static final a e = new a(1, 3);
    public static final a f = new a(1, 4);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                break;
            case 1:
                i iVar = (i) obj;
                iVar.getHandler().post(new C(iVar.n, 2));
                break;
            case 2:
                break;
            case 3:
                break;
            default:
                break;
        }
        return Unit.a;
    }
}
