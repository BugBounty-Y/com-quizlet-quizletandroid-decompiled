package com.quizlet.features.notes.upload.navigation;

import android.net.Uri;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.E;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.quizlet.assembly.compose.input.h;
import com.quizlet.assembly.compose.menu.g;
import com.quizlet.assembly.compose.menu.s;
import com.quizlet.data.model.m2;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.features.infra.folder.menu.composable.j;
import com.quizlet.features.infra.models.folders.AddMaterialFolderData;
import com.quizlet.features.setpage.termlist.data.n;
import com.quizlet.features.setpage.termlist.ui.i;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import java.util.List;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ Function2 d;
    public final /* synthetic */ kotlin.jvm.functions.c e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;
    public final /* synthetic */ Object k;

    public /* synthetic */ a(m2 m2Var, String str, kotlinx.collections.immutable.b bVar, AddMaterialFolderData addMaterialFolderData, H h, com.quizlet.features.notes.manager.a aVar, Function0 function0, Function2 function2, Function1 function1, kotlin.jvm.functions.c cVar) {
        this.f = m2Var;
        this.g = str;
        this.h = bVar;
        this.i = addMaterialFolderData;
        this.j = h;
        this.k = aVar;
        this.c = function0;
        this.d = function2;
        this.b = function1;
        this.e = cVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                E NavHost = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) this.h;
                int size = bVar != null ? bVar.size() : 0;
                Uri[] uriArr = new Uri[size];
                for (int i = 0; i < size; i++) {
                    uriArr[i] = bVar != null ? (Uri) bVar.get(i) : null;
                }
                f fVar = new f((m2) this.f, (String) this.g, uriArr, (AddMaterialFolderData) this.i);
                H h = (H) this.j;
                com.quizlet.features.notes.manager.a aVar = (com.quizlet.features.notes.manager.a) this.k;
                Function0 function0 = this.c;
                Function2 function2 = this.d;
                Function1 function1 = this.b;
                kotlin.jvm.functions.c cVar = this.e;
                N5.d(NavHost, fVar, new androidx.compose.runtime.internal.d(true, -495650759, new com.quizlet.features.blocks.ui.d(h, aVar, function0, function2, function1, cVar)));
                N5.d(NavHost, d.a, new androidx.compose.runtime.internal.d(true, 1699322530, new g((Object) h, (Object) function0, (InterfaceC4938g) function2, (Object) cVar, 7)));
                break;
            default:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                Function1 function12 = this.b;
                n nVar = (n) this.f;
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -1374546602, new i(nVar, function12, 1)), 3);
                DiagramData diagramData = nVar.b.a;
                if (diagramData != null) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, com.quizlet.features.setpage.termlist.ui.b.a, 3);
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -314390841, new h(16, diagramData, (DiagramJSBridge) this.g, this.c, false)), 3);
                }
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -123068993, new h(nVar, (s) this.h, (Function1) this.i, 17)), 3);
                List list = (List) ((InterfaceC0773a0) this.j).getValue();
                LazyColumn.q(list.size(), new androidx.compose.ui.viewinterop.b(18, new com.quizlet.features.practicetest.navigation.a(20), list), new com.quizlet.assembly.compose.menu.e(list, 11), new androidx.compose.runtime.internal.d(true, -632812321, new j(list, nVar, this.d, (kotlin.jvm.functions.d) this.k, this.e)));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ a(n nVar, Function1 function1, DiagramJSBridge diagramJSBridge, Function0 function0, s sVar, Function1 function12, InterfaceC0773a0 interfaceC0773a0, Function2 function2, kotlin.jvm.functions.d dVar, kotlin.jvm.functions.c cVar) {
        this.f = nVar;
        this.b = function1;
        this.g = diagramJSBridge;
        this.c = function0;
        this.h = sVar;
        this.i = function12;
        this.j = interfaceC0773a0;
        this.d = function2;
        this.k = dVar;
        this.e = cVar;
    }
}
