package com.quizlet.features.settings.composables.dialogs;

import androidx.compose.foundation.lazy.grid.A;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.Z5;
import com.google.android.gms.internal.mlkit_vision_camera.S1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3465h3;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.data.interactor.folderwithcreator.m;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.features.settings.viewmodels.o;
import com.quizlet.quizletandroid.ui.library.C4671p;
import com.quizlet.search.composables.I;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class e implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ InterfaceC4938g g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ e(int i, x xVar, InterfaceC0773a0 interfaceC0773a0, SearchType searchType, A a, kotlin.jvm.functions.c cVar, kotlin.jvm.functions.c cVar2, com.quizlet.search.viewmodels.A a2) {
        this.b = i;
        this.c = xVar;
        this.d = interfaceC0773a0;
        this.e = searchType;
        this.f = a;
        this.g = cVar;
        this.h = cVar2;
        this.i = a2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Integer) obj2).getClass();
                int iH = C0776c.H(this.b | 1);
                m mVar = (m) this.d;
                o oVar = (o) this.h;
                Function2 function2 = (Function2) this.i;
                AbstractC3465h3.a((com.quizlet.features.settings.data.models.f) this.c, mVar, (com.quizlet.quizletandroid.ui.navigationmanagers.h) this.e, (androidx.activity.compose.o) this.f, (Function0) this.g, oVar, function2, (InterfaceC0806l) obj, iH);
                break;
            case 1:
                androidx.compose.foundation.lazy.grid.i PagingGridList = (androidx.compose.foundation.lazy.grid.i) obj;
                androidx.paging.compose.d items = (androidx.paging.compose.d) obj2;
                Intrinsics.checkNotNullParameter(PagingGridList, "$this$PagingGridList");
                Intrinsics.checkNotNullParameter(items, "items");
                int i = this.b;
                androidx.compose.foundation.lazy.grid.i.o(PagingGridList, new com.quizlet.features.setpage.logging.a(i, 5), new androidx.compose.runtime.internal.d(true, 1868462882, new com.quizlet.features.questiontypes.mcq.ui.c(17, (x) this.c, (InterfaceC0773a0) this.d)));
                androidx.compose.foundation.lazy.grid.i.q(PagingGridList, items.c(), S1.c(items, new com.quizlet.qutils.android.f(17)), new C4671p(items, i, 3), new androidx.compose.runtime.internal.d(true, -788988407, new I(items, (SearchType) this.e, (A) this.f, (kotlin.jvm.functions.c) this.g, (kotlin.jvm.functions.c) this.h, (com.quizlet.search.viewmodels.A) this.i)), 8);
                break;
            default:
                ((Integer) obj2).getClass();
                int iH2 = C0776c.H(this.b | 1);
                Function0 function0 = (Function0) this.g;
                Function0 function02 = (Function0) this.i;
                Z5.b((x) this.c, (String) this.d, (String) this.e, (String) this.f, (String) this.h, function0, function02, (InterfaceC0806l) obj, iH2);
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ e(x xVar, String str, String str2, String str3, String str4, Function0 function0, Function0 function02, int i) {
        this.c = xVar;
        this.d = str;
        this.e = str2;
        this.f = str3;
        this.h = str4;
        this.g = function0;
        this.i = function02;
        this.b = i;
    }

    public /* synthetic */ e(com.quizlet.features.settings.data.models.f fVar, m mVar, com.quizlet.quizletandroid.ui.navigationmanagers.h hVar, androidx.activity.compose.o oVar, Function0 function0, o oVar2, Function2 function2, int i) {
        this.c = fVar;
        this.d = mVar;
        this.e = hVar;
        this.f = oVar;
        this.g = function0;
        this.h = oVar2;
        this.i = function2;
        this.b = i;
    }
}
