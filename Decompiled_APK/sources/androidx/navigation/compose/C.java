package androidx.navigation.compose;

import androidx.compose.animation.C0292t;
import androidx.compose.animation.a0;
import androidx.compose.animation.b0;
import androidx.compose.animation.n0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.runtime.W0;
import androidx.navigation.C1291m;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.features.folders.composables.AbstractC4249e;
import com.quizlet.features.folders.data.InterfaceC4318y0;
import com.quizlet.features.folders.data.K0;
import com.quizlet.features.folders.data.M0;
import com.quizlet.features.folders.data.N0;
import com.quizlet.features.folders.data.O0;
import com.quizlet.features.folders.data.P0;
import com.quizlet.features.folders.data.Q0;
import com.quizlet.features.folders.data.U;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class C implements Function1 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ Function1 b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;

    public /* synthetic */ C(androidx.collection.B b, C1276i c1276i, Function1 function1, Function1 function12, Function1 function13, W0 w0, InterfaceC0773a0 interfaceC0773a0) {
        this.c = b;
        this.d = c1276i;
        this.b = function1;
        this.e = function12;
        this.f = function13;
        this.g = w0;
        this.h = interfaceC0773a0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r5v9, types: [java.util.List] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        float f;
        ?? N0;
        switch (this.a) {
            case 0:
                C0292t c0292t = (C0292t) obj;
                if (!((List) ((W0) this.g).getValue()).contains(c0292t.a())) {
                    return androidx.compose.animation.E.l(a0.b, b0.b);
                }
                String str = ((C1291m) c0292t.a()).f;
                androidx.collection.B b = (androidx.collection.B) this.c;
                int iC = b.c(str);
                if (iC >= 0) {
                    f = b.c[iC];
                } else {
                    b.e(str, DefinitionKt.NO_Float_VALUE);
                    f = 0.0f;
                }
                if (!Intrinsics.b(((C1291m) c0292t.c()).f, ((C1291m) c0292t.a()).f)) {
                    f = (((Boolean) ((L0) ((C1276i) this.d).c).getValue()).booleanValue() || ((Boolean) ((InterfaceC0773a0) this.h).getValue()).booleanValue()) ? f - 1.0f : f + 1.0f;
                }
                b.e(((C1291m) c0292t.c()).f, f);
                return new androidx.compose.animation.J((a0) this.b.invoke(c0292t), (b0) ((Function1) this.e).invoke(c0292t), f, (n0) ((Function1) this.f).invoke(c0292t));
            default:
                androidx.compose.foundation.lazy.g FolderStudyMaterialsLazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(FolderStudyMaterialsLazyColumn, "$this$FolderStudyMaterialsLazyColumn");
                P0 p0 = (P0) this.c;
                boolean z = p0 instanceof com.quizlet.features.folders.data.L0;
                U u = (U) this.d;
                InterfaceC4318y0 interfaceC4318y0 = (InterfaceC4318y0) this.e;
                androidx.compose.foundation.lazy.A lazyListState = (androidx.compose.foundation.lazy.A) this.h;
                Function1 onFolderEvent = this.b;
                if (z) {
                    com.quizlet.features.folders.data.L0 l0 = (com.quizlet.features.folders.data.L0) p0;
                    l0.getClass();
                    ArrayList arrayList = new ArrayList();
                    for (Object obj2 : l0.a) {
                        com.quizlet.ui.models.content.listitem.o oVar = (com.quizlet.ui.models.content.listitem.o) obj2;
                        String str2 = l0.c;
                        if (str2 == null) {
                            str2 = "";
                        }
                        if (oVar.c(str2)) {
                            arrayList.add(obj2);
                        }
                    }
                    K0 k0 = l0.d;
                    Comparator comparatorB = k0.b();
                    if (comparatorB != null && (N0 = CollectionsKt.n0(arrayList, comparatorB)) != 0) {
                        arrayList = N0;
                    }
                    kotlinx.collections.immutable.b list = AbstractC3409x1.i(arrayList);
                    androidx.compose.foundation.lazy.g.p(FolderStudyMaterialsLazyColumn, Integer.valueOf(k0.a), new androidx.compose.runtime.internal.d(true, -98811130, new com.quizlet.assembly.compose.input.m(12, k0, onFolderEvent)), 2);
                    Q0 q0 = u.a;
                    boolean z2 = q0.h;
                    Intrinsics.checkNotNullParameter(FolderStudyMaterialsLazyColumn, "<this>");
                    Intrinsics.checkNotNullParameter(list, "list");
                    com.quizlet.assembly.compose.menu.s assemblyMenuState = (com.quizlet.assembly.compose.menu.s) this.f;
                    Intrinsics.checkNotNullParameter(assemblyMenuState, "assemblyMenuState");
                    com.quizlet.features.folders.menu.u studyMaterialItemsMenuState = (com.quizlet.features.folders.menu.u) this.g;
                    Intrinsics.checkNotNullParameter(studyMaterialItemsMenuState, "studyMaterialItemsMenuState");
                    Intrinsics.checkNotNullParameter(onFolderEvent, "onFolderEvent");
                    Intrinsics.checkNotNullParameter(lazyListState, "lazyListState");
                    FolderStudyMaterialsLazyColumn.q(list.size(), new androidx.compose.ui.viewinterop.b(12, new x(10), list), new com.quizlet.features.folders.addtofolder.composables.g(list, 1), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.features.folders.composables.N(list, onFolderEvent, z2, q0.r, lazyListState, studyMaterialItemsMenuState, assemblyMenuState)));
                    Q4.k(FolderStudyMaterialsLazyColumn, interfaceC4318y0, lazyListState, onFolderEvent);
                } else if (Intrinsics.b(p0, M0.a)) {
                    androidx.compose.foundation.lazy.g.p(FolderStudyMaterialsLazyColumn, null, new androidx.compose.runtime.internal.d(true, -2041495420, new com.quizlet.features.folders.composables.a0(u, onFolderEvent, 1)), 3);
                    Q4.k(FolderStudyMaterialsLazyColumn, interfaceC4318y0, lazyListState, onFolderEvent);
                } else if (p0 instanceof O0) {
                    Integer num = u.a.c;
                    FolderStudyMaterialsLazyColumn.q(num != null ? num.intValue() : 8, null, androidx.compose.foundation.lazy.o.c, AbstractC4249e.a);
                } else {
                    if (!Intrinsics.b(p0, N0.a)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    androidx.compose.foundation.lazy.g.p(FolderStudyMaterialsLazyColumn, null, new androidx.compose.runtime.internal.d(true, -705200475, new com.quizlet.features.folders.addtofolder.composables.s(3, onFolderEvent)), 3);
                }
                return Unit.a;
        }
    }

    public /* synthetic */ C(P0 p0, U u, InterfaceC4318y0 interfaceC4318y0, com.quizlet.assembly.compose.menu.s sVar, com.quizlet.features.folders.menu.u uVar, androidx.compose.foundation.lazy.A a, Function1 function1) {
        this.c = p0;
        this.d = u;
        this.e = interfaceC4318y0;
        this.f = sVar;
        this.g = uVar;
        this.h = a;
        this.b = function1;
    }
}
