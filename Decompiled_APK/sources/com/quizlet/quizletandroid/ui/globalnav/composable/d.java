package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.appcompat.app.y;
import androidx.compose.foundation.layout.H0;
import androidx.compose.foundation.layout.z0;
import androidx.compose.foundation.lazy.grid.A;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.I;
import androidx.navigation.B;
import androidx.navigation.H;
import androidx.navigation.compose.L;
import com.google.android.gms.internal.mlkit_vision_barcode.A0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3152g6;
import com.google.android.gms.internal.mlkit_vision_camera.S1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.c7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.h7;
import com.quizlet.data.model.C2;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.quizletandroid.ui.library.C4671p;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import com.quizlet.search.viewmodels.AbstractC4797c;
import com.quizlet.search.viewmodels.D;
import com.quizlet.studiablemodels.DefaultQuestionSectionData;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class d implements Function2 {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ d(int i, InterfaceC4938g interfaceC4938g, SearchType searchType, A a, AbstractC4797c abstractC4797c, int i2) {
        this.a = i2;
        this.b = i;
        this.c = interfaceC4938g;
        this.d = searchType;
        this.e = a;
        this.f = abstractC4797c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                I i = (I) this.c;
                com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar = (com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.e;
                H h = (H) this.f;
                E4.b(i, (C4739h) this.d, aVar, h, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                ((Integer) obj2).intValue();
                L4.a((H0) this.c, (kotlinx.collections.immutable.b) this.d, (B) this.e, (Function1) this.f, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case 2:
                ((Integer) obj2).getClass();
                E6.j((com.quizlet.assembly.compose.modals.x) this.c, (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.data.m) this.d, (androidx.compose.ui.n) this.e, (Function1) this.f, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case 3:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(1);
                com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar = (com.quizlet.features.infra.ui.feedback.sound.soundeffect.e) this.f;
                int i2 = this.b;
                com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.d((G) this.c, (androidx.compose.ui.q) this.d, (com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t) this.e, eVar, i2, (InterfaceC0806l) obj, iH2);
                break;
            case 4:
                ((Integer) obj2).getClass();
                int iH3 = C0776c.H(this.b | 1);
                androidx.compose.ui.q qVar = (androidx.compose.ui.q) this.e;
                Function1 function1 = (Function1) this.f;
                c7.b((DefaultQuestionSectionData) this.c, (DefaultQuestionSectionData) this.d, qVar, function1, (InterfaceC0806l) obj, iH3);
                break;
            case 5:
                ((Integer) obj2).getClass();
                int iH4 = C0776c.H(this.b | 1);
                com.quizlet.quizletandroid.ui.studymodes.testmode.start.j jVar = (com.quizlet.quizletandroid.ui.studymodes.testmode.start.j) this.e;
                androidx.compose.ui.q qVar2 = (androidx.compose.ui.q) this.f;
                h7.f((com.quizlet.quizletandroid.ui.studymodes.testmode.start.j) this.c, (com.quizlet.quizletandroid.ui.studymodes.testmode.start.j) this.d, jVar, qVar2, (InterfaceC0806l) obj, iH4);
                break;
            case 6:
                ((Integer) obj2).getClass();
                int iH5 = C0776c.H(this.b | 1);
                C2 c2 = (C2) this.c;
                androidx.appcompat.view.a aVar2 = (androidx.appcompat.view.a) this.e;
                androidx.glance.n nVar = (androidx.glance.n) this.f;
                okhttp3.internal.platform.m.a(c2, (kotlinx.collections.immutable.b) this.d, aVar2, nVar, (InterfaceC0806l) obj, iH5);
                break;
            case 7:
                ((Integer) obj2).getClass();
                int iH6 = C0776c.H(this.b | 1);
                C2 c22 = (C2) this.c;
                androidx.appcompat.view.a aVar3 = (androidx.appcompat.view.a) this.e;
                androidx.glance.p pVar = (androidx.glance.p) this.f;
                _COROUTINE.a.d(c22, (kotlinx.collections.immutable.b) this.d, aVar3, pVar, (InterfaceC0806l) obj, iH6);
                break;
            case 8:
                androidx.compose.foundation.lazy.grid.i PagingGridList = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items, "items");
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList, items.c(), S1.c(items, new com.quizlet.qutils.android.f(15)), new C4671p(items, this.b, 1), new androidx.compose.runtime.internal.d(true, -1506343096, new L(items, (Function2) this.c, (SearchType) this.d, (A) this.e, (com.quizlet.search.viewmodels.u) this.f, 2)), 8);
                break;
            case 9:
                androidx.compose.foundation.lazy.grid.i PagingGridList2 = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items2 = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList2, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items2, "items");
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList2, items2.c(), S1.c(items2, new com.quizlet.qutils.android.f(16)), new C4671p(items2, this.b, 2), new androidx.compose.runtime.internal.d(true, -1828321490, new L(items2, (kotlin.jvm.functions.c) this.c, (SearchType) this.d, (A) this.e, (com.quizlet.search.viewmodels.x) this.f, 3)), 8);
                break;
            case 10:
                androidx.compose.foundation.lazy.grid.i PagingGridList3 = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items3 = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList3, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items3, "items");
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList3, items3.c(), S1.c(items3, new com.quizlet.qutils.android.f(18)), new C4671p(items3, this.b, 4), new androidx.compose.runtime.internal.d(true, -1306512543, new L(items3, (kotlin.jvm.functions.c) this.c, (SearchType) this.d, (A) this.e, (D) this.f, 4)), 8);
                break;
            case 11:
                ((Integer) obj2).getClass();
                int iH7 = C0776c.H(this.b | 1);
                Function0 function0 = (Function0) this.e;
                z0 z0Var = (z0) this.f;
                A0.f((com.quizlet.search.data.i) this.c, (Function1) this.d, function0, z0Var, (InterfaceC0806l) obj, iH7);
                break;
            case 12:
                ((Integer) obj2).intValue();
                A0.c((z0) this.c, (com.quizlet.search.data.h) this.d, (Function1) this.e, (Function0) this.f, (InterfaceC0806l) obj, C0776c.H(this.b | 1));
                break;
            case 13:
                androidx.compose.foundation.lazy.grid.i PagingGridList4 = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items4 = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList4, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items4, "items");
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList4, items4.c(), S1.c(items4, new com.quizlet.qutils.android.f(19)), new C4671p(items4, this.b, 5), new androidx.compose.runtime.internal.d(true, 1891863437, new L(items4, (Function2) this.c, (SearchType) this.d, (A) this.e, (com.quizlet.search.viewmodels.G) this.f, 5)), 8);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH8 = C0776c.H(1);
                Function1 function12 = (Function1) this.f;
                AbstractC3152g6.b((y) this.c, (androidx.compose.ui.q) this.d, (Integer) this.e, function12, (InterfaceC0806l) obj, iH8, this.b);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ d(y yVar, androidx.compose.ui.q qVar, Integer num, Function1 function1, int i, int i2) {
        this.a = 14;
        this.c = yVar;
        this.d = qVar;
        this.e = num;
        this.f = function1;
        this.b = i2;
    }

    public /* synthetic */ d(G g, androidx.compose.ui.q qVar, com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t tVar, com.quizlet.features.infra.ui.feedback.sound.soundeffect.e eVar, int i, int i2) {
        this.a = 3;
        this.c = g;
        this.d = qVar;
        this.e = tVar;
        this.f = eVar;
        this.b = i;
    }

    public /* synthetic */ d(Object obj, Object obj2, Object obj3, Object obj4, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.d = obj2;
        this.e = obj3;
        this.f = obj4;
        this.b = i;
    }
}
