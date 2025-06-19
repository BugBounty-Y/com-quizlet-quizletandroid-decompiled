package com.quizlet.quizletandroid.ui.common.ads;

import android.content.Context;
import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.C1480f;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ E k;
    public final /* synthetic */ ViewGroup l;
    public final /* synthetic */ WindowManager m;
    public final /* synthetic */ Map n;
    public final /* synthetic */ J o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(E e, ViewGroup viewGroup, WindowManager windowManager, Map map, J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
        this.l = viewGroup;
        this.m = windowManager;
        this.n = map;
        this.o = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        w wVar = new w(this.k, this.l, this.m, this.n, this.o, hVar);
        wVar.j = obj;
        return wVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((Pair) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        final int i = 0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Pair pair = (Pair) this.j;
        C4634a c4634a = (C4634a) pair.a;
        Map map = (Map) pair.b;
        final I i2 = this.k.c;
        com.quizlet.ads.c cVar = c4634a.a;
        Map mapC = this.n;
        if (mapC == null) {
            mapC = V.c();
        }
        H input = new H(cVar, this.l, this.m, c4634a, map, mapC, new C1480f(this.o, 13));
        i2.getClass();
        ViewGroup viewGroup = input.b;
        Intrinsics.checkNotNullParameter(input, "input");
        com.quizlet.openwrap.b bVar = new com.quizlet.openwrap.b();
        Context context = viewGroup.getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        final com.pubmatic.sdk.openwrap.banner.c cVar2 = (com.pubmatic.sdk.openwrap.banner.c) i2.b.a(context);
        viewGroup.removeAllViews();
        viewGroup.addView(cVar2);
        Context context2 = viewGroup.getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        C4634a c4634a2 = input.d;
        Intrinsics.checkNotNullParameter(c4634a2, "<this>");
        Intrinsics.checkNotNullParameter(context2, "context");
        String input2 = context2.getString(c4634a2.a.a);
        Intrinsics.checkNotNullExpressionValue(input2, "getString(...)");
        final int i3 = 1;
        i2.a.getClass();
        Intrinsics.checkNotNullParameter(input2, "input");
        String strSubstring = input2.substring(StringsKt.Q(input2, "/", 0, 6) + 1, input2.length());
        Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
        Context context3 = viewGroup.getContext();
        Intrinsics.d(context3);
        Intrinsics.checkNotNullParameter(c4634a2, "<this>");
        Intrinsics.checkNotNullParameter(context3, "context");
        String string = context3.getString(c4634a2.a.a);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        com.quizlet.ads.c cVar3 = input.a;
        com.pubmatic.sdk.openwrap.eventhandler.dfp.b bVar2 = (com.pubmatic.sdk.openwrap.eventhandler.dfp.b) i2.c.a(new C4640g(context3, string, (com.google.android.gms.ads.h) i2.d.a(new C4642i(viewGroup, input.c, cVar3))));
        bVar2.setConfigListener(new com.google.firebase.tracing.a(23, i2, input));
        cVar2.init("159540", 10172, strSubstring, bVar2);
        final boolean zB = cVar3.b();
        com.facebook.appevents.m.n(viewGroup, new G(new com.quizlet.login.magiclink.ui.e(cVar2, 10), 2));
        com.facebook.appevents.m.n(viewGroup, new G(new Function0() { // from class: com.quizlet.quizletandroid.ui.common.ads.F
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                com.pubmatic.sdk.openwrap.banner.c cVar4 = cVar2;
                boolean z = zB;
                I i4 = i2;
                switch (i) {
                    case 0:
                        i4.getClass();
                        if (z) {
                            cVar4.resumeAutoRefresh();
                            Unit unit = Unit.a;
                        }
                        break;
                    default:
                        i4.getClass();
                        if (z) {
                            cVar4.pauseAutoRefresh();
                            Unit unit2 = Unit.a;
                        }
                        break;
                }
                return Unit.a;
            }
        }, i3));
        com.facebook.appevents.m.n(viewGroup, new G(new Function0() { // from class: com.quizlet.quizletandroid.ui.common.ads.F
            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                com.pubmatic.sdk.openwrap.banner.c cVar4 = cVar2;
                boolean z = zB;
                I i4 = i2;
                switch (i3) {
                    case 0:
                        i4.getClass();
                        if (z) {
                            cVar4.resumeAutoRefresh();
                            Unit unit = Unit.a;
                        }
                        break;
                    default:
                        i4.getClass();
                        if (z) {
                            cVar4.pauseAutoRefresh();
                            Unit unit2 = Unit.a;
                        }
                        break;
                }
                return Unit.a;
            }
        }, i));
        cVar2.setBidEventListener(bVar);
        cVar2.setListener(bVar);
        return new kotlin.v(new C4639f(cVar2, bVar.a, new com.quizlet.login.authentication.login.a(cVar2)), c4634a, map);
    }
}
