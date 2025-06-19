package coil3;

import java.util.ArrayList;
import java.util.List;
import kotlin.Pair;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

/* loaded from: classes.dex */
public final /* synthetic */ class k implements Function0 {
    public final /* synthetic */ int a;

    public /* synthetic */ k(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return (coil3.disk.i) coil3.disk.j.a.getValue();
            case 1:
                List listN0 = CollectionsKt.n0((List) coil3.util.j.a.getValue(), new androidx.constraintlayout.core.e(20));
                ArrayList arrayList = new ArrayList();
                int size = listN0.size();
                for (int i = 0; i < size; i++) {
                    Intrinsics.e((coil3.network.okhttp.internal.d) listN0.get(i), "null cannot be cast to non-null type coil3.util.FetcherServiceLoaderTarget<kotlin.Any>");
                    arrayList.add(new Pair(new coil3.network.j(new androidx.lifecycle.compose.f(9)), K.a(y.class)));
                }
                return arrayList;
            default:
                List listN02 = CollectionsKt.n0((List) coil3.util.j.b.getValue(), new androidx.constraintlayout.core.e(21));
                ArrayList arrayList2 = new ArrayList();
                if (listN02.size() <= 0) {
                    return arrayList2;
                }
                listN02.get(0).getClass();
                throw new ClassCastException();
        }
    }
}
