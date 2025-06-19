package androidx.glance.appwidget;

import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class W extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ String k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public W(String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = str2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        W w = new W(this.k, this.l, hVar);
        w.j = obj;
        return w;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((W) create((androidx.datastore.preferences.core.b) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.datastore.preferences.core.b bVar = (androidx.datastore.preferences.core.b) this.j;
        androidx.datastore.preferences.core.b bVarG = bVar.g();
        androidx.datastore.preferences.core.f key = X.g;
        Set set = (Set) bVar.c(key);
        if (set == null) {
            set = kotlin.collections.M.a;
        }
        String str = this.k;
        LinkedHashSet linkedHashSetG = kotlin.collections.b0.g(set, str);
        Intrinsics.checkNotNullParameter(key, "key");
        bVarG.f(key, linkedHashSetG);
        androidx.datastore.preferences.core.f key2 = P.a(X.d, str);
        Intrinsics.checkNotNullParameter(key2, "key");
        bVarG.f(key2, this.l);
        return bVarG.h();
    }
}
