package androidx.compose.foundation.pager;

import androidx.compose.foundation.text.selection.C0534o;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class H extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(int i, Function0 function0) {
        super(0);
        this.a = 0;
        this.b = i;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return new C0466e(this.b, DefinitionKt.NO_Float_VALUE, (Function0) this.c);
            case 1:
                return Integer.valueOf(((C0534o) this.c).f.f(this.b));
            default:
                ((Function1) this.c).invoke(Integer.valueOf(this.b));
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ H(Object obj, int i, int i2) {
        super(0);
        this.a = i2;
        this.c = obj;
        this.b = i;
    }
}
