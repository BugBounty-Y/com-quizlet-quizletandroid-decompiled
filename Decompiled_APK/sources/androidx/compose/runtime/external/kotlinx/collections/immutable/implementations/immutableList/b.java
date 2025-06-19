package androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList;

import android.view.View;
import androidx.core.view.L;
import androidx.core.view.V;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Collection b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, Collection collection) {
        super(1);
        this.a = i;
        this.b = collection;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Collection<?> collection = this.b;
        switch (this.a) {
            case 0:
                return Boolean.valueOf(collection.contains(obj));
            case 1:
                return Boolean.valueOf(collection.contains(obj));
            case 2:
                return Boolean.valueOf(((List) obj).retainAll(collection));
            default:
                Map.Entry entry = (Map.Entry) obj;
                Intrinsics.checkNotNullParameter(entry, "entry");
                View view = (View) entry.getValue();
                WeakHashMap weakHashMap = V.a;
                return Boolean.valueOf(CollectionsKt.F(collection, L.f(view)));
        }
    }
}
