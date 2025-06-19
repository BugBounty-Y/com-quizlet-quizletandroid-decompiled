package com.quizlet.quizletandroid.initializers.ads;

import android.os.RemoteException;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.ads.internal.client.C0;
import com.google.android.gms.ads.internal.client.InterfaceC1585b0;
import com.google.android.gms.ads.internal.client.zzfr;
import com.google.android.gms.ads.p;
import java.util.ArrayList;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ MobileAdsInitializer k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(MobileAdsInitializer mobileAdsInitializer, h hVar) {
        super(2, hVar);
        this.k = mobileAdsInitializer;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        c cVar = new c(this.k, hVar);
        cVar.j = obj;
        return cVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((Boolean) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        int i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Boolean bool = (Boolean) this.j;
        this.k.getClass();
        if (Intrinsics.b(bool, Boolean.TRUE)) {
            i = 1;
        } else if (Intrinsics.b(bool, Boolean.FALSE)) {
            i = 0;
        } else {
            if (bool != null) {
                throw new NoWhenBranchMatchedException();
            }
            i = -1;
        }
        p pVar = C0.e().g;
        pVar.getClass();
        ArrayList arrayList = new ArrayList();
        int i2 = pVar.a;
        if (i2 != -1 && i2 != 0 && i2 != 1) {
            com.google.android.gms.ads.internal.util.client.i.h("Invalid value passed to setTagForChildDirectedTreatment: " + i2);
            i2 = -1;
        }
        int i3 = pVar.b;
        if (i3 != -1 && i3 != 0 && i3 != 1) {
            com.google.android.gms.ads.internal.util.client.i.h("Invalid value passed to setTagForUnderAgeOfConsent: " + i3);
            i3 = -1;
        }
        String str = pVar.c;
        if (str == null || "".equals(str)) {
            str = null;
        } else if (!"G".equals(str) && !"PG".equals(str) && !"T".equals(str) && !"MA".equals(str)) {
            com.google.android.gms.ads.internal.util.client.i.h("Invalid value passed to setMaxAdContentRating: ".concat(str));
            str = null;
        }
        arrayList.clear();
        arrayList.addAll(pVar.d);
        if (i != -1 && i != 0 && i != 1) {
            com.google.android.gms.ads.internal.util.client.i.h("Invalid value passed to setTagForChildDirectedTreatment: " + i);
            i = i2;
        }
        p pVar2 = new p(i, i3, str, arrayList);
        Intrinsics.checkNotNullExpressionValue(pVar2, "build(...)");
        C0 c0E = C0.e();
        c0E.getClass();
        synchronized (c0E.e) {
            try {
                p pVar3 = c0E.g;
                c0E.g = pVar2;
                InterfaceC1585b0 interfaceC1585b0 = c0E.f;
                if (interfaceC1585b0 != null) {
                    if (pVar3.a != i || pVar3.b != i3) {
                        try {
                            interfaceC1585b0.r0(new zzfr(pVar2));
                        } catch (RemoteException e) {
                            com.google.android.gms.ads.internal.util.client.i.f("Unable to set request configuration parcel.", e);
                        }
                    }
                }
            } finally {
            }
        }
        return Unit.a;
    }
}
