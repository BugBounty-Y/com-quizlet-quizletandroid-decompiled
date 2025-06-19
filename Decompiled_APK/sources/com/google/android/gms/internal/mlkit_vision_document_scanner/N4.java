package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.view.ViewGroup;
import android.view.WindowManager;
import androidx.datastore.core.C1087t;
import androidx.paging.C1319i;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes2.dex */
public abstract class N4 {
    public static final /* synthetic */ int a = 0;

    public static androidx.paging.J0 a(com.quizlet.quizletandroid.ui.common.ads.E e, int i, String str, ViewGroup adContainer, WindowManager windowManager, LinkedHashMap linkedHashMap, int i2) {
        int i3 = 5;
        kotlin.coroutines.h hVar = null;
        String str2 = (i2 & 2) != 0 ? null : str;
        kotlin.collections.K viewsLinkedToVisibility = kotlin.collections.K.a;
        boolean z = (i2 & 32) != 0;
        LinkedHashMap linkedHashMap2 = (i2 & 64) != 0 ? null : linkedHashMap;
        Intrinsics.checkNotNullParameter(adContainer, "adContainer");
        Intrinsics.checkNotNullParameter(windowManager, "windowManager");
        Intrinsics.checkNotNullParameter(viewsLinkedToVisibility, "viewsLinkedToVisibility");
        kotlin.jvm.internal.J j = new kotlin.jvm.internal.J();
        j.a = kotlin.collections.V.c();
        ArrayList arrayListC0 = CollectionsKt.c0(kotlin.collections.A.b(adContainer), viewsLinkedToVisibility);
        C1087t c1087t = new C1087t(new com.quizlet.quizletandroid.ui.common.ads.u(e, i, str2, null));
        com.quizlet.quizletandroid.ui.common.ads.v block = new com.quizlet.quizletandroid.ui.common.ads.v(e, null);
        Intrinsics.checkNotNullParameter(c1087t, "<this>");
        Intrinsics.checkNotNullParameter(block, "block");
        androidx.compose.material3.internal.H h = new androidx.compose.material3.internal.H(12, c1087t, block);
        AbstractC5040y abstractC5040y = e.f;
        InterfaceC4992i interfaceC4992iS = kotlinx.coroutines.flow.e0.s(h, abstractC5040y);
        com.quizlet.quizletandroid.ui.common.ads.w block2 = new com.quizlet.quizletandroid.ui.common.ads.w(e, adContainer, windowManager, linkedHashMap2, j, null);
        Intrinsics.checkNotNullParameter(interfaceC4992iS, "<this>");
        Intrinsics.checkNotNullParameter(block2, "block");
        androidx.compose.material3.internal.H h2 = new androidx.compose.material3.internal.H(11, interfaceC4992iS, block2);
        AbstractC5040y abstractC5040y2 = e.e;
        InterfaceC4992i interfaceC4992iS2 = kotlinx.coroutines.flow.e0.s(h2, abstractC5040y2);
        com.quizlet.quizletandroid.ui.common.ads.A block3 = new com.quizlet.quizletandroid.ui.common.ads.A(e, j, null);
        Intrinsics.checkNotNullParameter(interfaceC4992iS2, "<this>");
        Intrinsics.checkNotNullParameter(block3, "block");
        C1319i c1319i = new C1319i(block3, (kotlin.coroutines.h) null);
        int i4 = kotlinx.coroutines.flow.G.a;
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        kotlinx.coroutines.channels.a aVar = kotlinx.coroutines.channels.a.a;
        InterfaceC4992i interfaceC4992iS3 = kotlinx.coroutines.flow.e0.s(new kotlinx.coroutines.flow.internal.m(c1319i, interfaceC4992iS2, nVar, -2, aVar), abstractC5040y);
        com.quizlet.quizletandroid.ui.common.ads.B block4 = new com.quizlet.quizletandroid.ui.common.ads.B(e, null);
        Intrinsics.checkNotNullParameter(interfaceC4992iS3, "<this>");
        Intrinsics.checkNotNullParameter(block4, "block");
        kotlinx.coroutines.flow.internal.m mVar = new kotlinx.coroutines.flow.internal.m(new C1319i(block4, (kotlin.coroutines.h) null), interfaceC4992iS3, nVar, -2, aVar);
        Intrinsics.checkNotNullParameter(mVar, "<this>");
        C1087t c1087t2 = new C1087t(mVar, 7);
        com.quizlet.quizletandroid.ui.common.ads.C block5 = new com.quizlet.quizletandroid.ui.common.ads.C(z, adContainer, arrayListC0, null);
        Intrinsics.checkNotNullParameter(c1087t2, "<this>");
        Intrinsics.checkNotNullParameter(block5, "block");
        androidx.paging.J0 j0 = new androidx.paging.J0(c1087t2, new com.quizlet.qutils.coroutines.j(block5, null), 5);
        com.quizlet.quizletandroid.ui.common.ads.D block6 = new com.quizlet.quizletandroid.ui.common.ads.D(z, adContainer, arrayListC0, null);
        Intrinsics.checkNotNullParameter(j0, "<this>");
        Intrinsics.checkNotNullParameter(block6, "block");
        InterfaceC4992i interfaceC4992iS4 = kotlinx.coroutines.flow.e0.s(new androidx.paging.J0(j0, new com.quizlet.qutils.coroutines.k(block6, null), 5), abstractC5040y2);
        Intrinsics.checkNotNullParameter(interfaceC4992iS4, "<this>");
        com.quizlet.features.flashcards.helpers.d dVar = new com.quizlet.features.flashcards.helpers.d(interfaceC4992iS4, 4);
        com.google.firebase.sessions.H block7 = new com.google.firebase.sessions.H(3, 5, null);
        int i5 = com.quizlet.qutils.coroutines.c.a;
        Intrinsics.checkNotNullParameter(dVar, "<this>");
        Intrinsics.checkNotNullParameter(block7, "block");
        return new androidx.paging.J0(dVar, new C1319i((Object) block7, hVar, i3));
    }
}
