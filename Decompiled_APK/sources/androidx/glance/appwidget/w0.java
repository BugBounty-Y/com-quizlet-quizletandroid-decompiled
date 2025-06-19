package androidx.glance.appwidget;

import android.appwidget.AppWidgetProviderInfo;
import android.content.Context;
import androidx.datastore.core.InterfaceC1076h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class w0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Context k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w0(Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new w0(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            X x = new X(this.k);
            this.j = 1;
            String packageName = x.a.getPackageName();
            List<AppWidgetProviderInfo> installedProviders = x.b.getInstalledProviders();
            ArrayList arrayList = new ArrayList();
            for (Object obj2 : installedProviders) {
                if (Intrinsics.b(((AppWidgetProviderInfo) obj2).provider.getPackageName(), packageName)) {
                    arrayList.add(obj2);
                }
            }
            ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                arrayList2.add(((AppWidgetProviderInfo) it2.next()).provider.getClassName());
            }
            Object objA = ((InterfaceC1076h) x.c.getValue()).a(new T(CollectionsKt.A0(arrayList2), null), this);
            if (objA != kotlin.coroutines.intrinsics.a.a) {
                objA = Unit.a;
            }
            if (objA == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
