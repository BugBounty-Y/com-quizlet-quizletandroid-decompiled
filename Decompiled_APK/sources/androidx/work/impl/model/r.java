package androidx.work.impl.model;

import java.util.HashMap;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final /* synthetic */ class r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ t b;

    public /* synthetic */ r(t tVar, int i) {
        this.a = i;
        this.b = tVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        HashMap map = (HashMap) obj;
        switch (this.a) {
            case 0:
                this.b.b(map);
                break;
            default:
                this.b.a(map);
                break;
        }
        return Unit.a;
    }
}
