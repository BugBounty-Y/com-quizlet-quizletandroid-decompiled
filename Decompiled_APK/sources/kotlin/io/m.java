package kotlin.io;

import java.util.ArrayList;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes3.dex */
public final class m extends r implements Function1 {
    public final /* synthetic */ ArrayList a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public m(ArrayList arrayList) {
        super(1);
        this.a = arrayList;
    }

    public final void a(String it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        this.a.add(it2);
    }

    @Override // kotlin.jvm.functions.Function1
    public final /* bridge */ /* synthetic */ Object invoke(Object obj) {
        a((String) obj);
        return Unit.a;
    }
}
