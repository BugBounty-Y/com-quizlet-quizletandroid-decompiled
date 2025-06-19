package androidx.navigation.compose;

import androidx.compose.animation.core.P;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.ui.platform.ComposeView;
import androidx.navigation.C1291m;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.generated.enums.y1;
import com.quizlet.login.oldlogin.LaunchParentEmailFragment;
import com.quizlet.ui.compose.d0;
import com.skydoves.balloon.compose.BalloonWindow;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.navigation.compose.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class C1279l implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ C1279l(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = z;
        this.d = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                final C1291m c1291m = (C1291m) this.c;
                final boolean z = this.b;
                final androidx.compose.runtime.snapshots.q qVar = (androidx.compose.runtime.snapshots.q) this.d;
                androidx.lifecycle.H h = new androidx.lifecycle.H() { // from class: androidx.navigation.compose.n
                    @Override // androidx.lifecycle.H
                    public final void d(androidx.lifecycle.J j, androidx.lifecycle.A a) {
                        C1291m c1291m2 = c1291m;
                        boolean z2 = z;
                        androidx.compose.runtime.snapshots.q qVar2 = qVar;
                        if (z2 && !qVar2.contains(c1291m2)) {
                            qVar2.add(c1291m2);
                        }
                        if (a == androidx.lifecycle.A.ON_START && !qVar2.contains(c1291m2)) {
                            qVar2.add(c1291m2);
                        }
                        if (a == androidx.lifecycle.A.ON_STOP) {
                            qVar2.remove(c1291m2);
                        }
                    }
                };
                c1291m.h.j.a(h);
                return new P(12, c1291m, h);
            case 1:
                androidx.compose.foundation.lazy.g LazyRow = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyRow, "$this$LazyRow");
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) this.c;
                LazyRow.q(bVar.size(), null, new com.quizlet.assembly.compose.menu.e(bVar, 1), new androidx.compose.runtime.internal.d(true, -1091073711, new com.quizlet.explanations.questiondetail.ui.composables.p(bVar, this.b, (Function2) this.d)));
                return Unit.a;
            case 2:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                if (this.b) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -1100888023, new com.quizlet.features.folders.addtofolder.composables.s(4, (Function1) this.c)), 3);
                }
                Function1 function1 = (Function1) this.d;
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -513863858, new com.quizlet.features.folders.addtofolder.composables.s(5, function1)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 1200260101, new com.quizlet.features.folders.addtofolder.composables.s(6, function1)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 1463957126, new com.quizlet.features.folders.addtofolder.composables.s(7, function1)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, com.quizlet.features.home.composables.b.a, 3);
                return Unit.a;
            case 3:
                com.quizlet.features.infra.folder.menu.screenstates.c it2 = (com.quizlet.features.infra.folder.menu.screenstates.c) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(it2.b);
                boolean z2 = this.b;
                com.quizlet.features.infra.folder.menu.data.b bVar2 = (com.quizlet.features.infra.folder.menu.data.b) this.c;
                com.quizlet.features.infra.folder.menu.viewmodel.m mVar = (com.quizlet.features.infra.folder.menu.viewmodel.m) this.d;
                if (z2) {
                    linkedHashSetZ0.add(Long.valueOf(bVar2.a));
                } else {
                    long j = bVar2.a;
                    mVar.getClass();
                    if (linkedHashSetZ0.contains(Long.valueOf(j))) {
                        linkedHashSetZ0.remove(Long.valueOf(j));
                    } else {
                        linkedHashSetZ0.add(Long.valueOf(j));
                    }
                }
                if (!linkedHashSetZ0.contains(Long.valueOf(bVar2.a))) {
                    List list = bVar2.d;
                    ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
                    Iterator it3 = list.iterator();
                    while (it3.hasNext()) {
                        arrayList.add(Long.valueOf(((com.quizlet.features.infra.folder.menu.data.f) it3.next()).getId()));
                    }
                    linkedHashSetZ0.removeAll(CollectionsKt.A0(arrayList));
                }
                FolderLogger folderLogger = mVar.b;
                String str = mVar.m;
                if (str == null) {
                    Intrinsics.m("studyMaterialId");
                    throw null;
                }
                y1 y1Var = mVar.l;
                if (y1Var == null) {
                    Intrinsics.m("studyMaterialType");
                    throw null;
                }
                long j2 = bVar2.a;
                folderLogger.D(j2, str, y1Var, linkedHashSetZ0.contains(Long.valueOf(j2)));
                return com.quizlet.features.infra.folder.menu.screenstates.c.c(it2, AbstractC3409x1.j(linkedHashSetZ0), !linkedHashSetZ0.equals(com.quizlet.features.infra.folder.menu.viewmodel.m.t(it2.a)));
            case 4:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                LinkedHashMap linkedHashMap = (LinkedHashMap) this.c;
                com.quizlet.login.oldlogin.o oVar = (com.quizlet.login.oldlogin.o) this.d;
                if (zBooleanValue && this.b) {
                    linkedHashMap.remove("email");
                    com.quizlet.login.oldlogin.b bVar3 = com.quizlet.login.oldlogin.b.b;
                    com.google.android.gms.internal.appset.e eVar = oVar.f;
                    eVar.getClass();
                    Intrinsics.checkNotNullParameter("email", "authProvider");
                    EventLoggerExt.a((EventLogger) eVar.b, "authentication_parent_email_request", new com.quizlet.features.notes.logging.b("email", true));
                    oVar.t.j(new LaunchParentEmailFragment(linkedHashMap, "email", bVar3));
                } else {
                    oVar.E(linkedHashMap);
                }
                return Unit.a;
            default:
                Intrinsics.checkNotNullParameter((ComposeView) obj, "it");
                if (this.b) {
                    int iOrdinal = ((d0) this.c).ordinal();
                    InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) this.d;
                    if (iOrdinal == 0) {
                        BalloonWindow balloonWindow = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow != null) {
                            BalloonWindow.DefaultImpls.showAlignTop$default(balloonWindow, 0, 0, 3, null);
                        }
                    } else if (iOrdinal == 1) {
                        BalloonWindow balloonWindow2 = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow2 != null) {
                            BalloonWindow.DefaultImpls.showAlignBottom$default(balloonWindow2, 0, 0, 3, null);
                        }
                    } else if (iOrdinal == 2) {
                        BalloonWindow balloonWindow3 = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow3 != null) {
                            BalloonWindow.DefaultImpls.showAlignStart$default(balloonWindow3, 0, 0, 3, null);
                        }
                    } else if (iOrdinal == 3) {
                        BalloonWindow balloonWindow4 = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow4 != null) {
                            BalloonWindow.DefaultImpls.showAlignEnd$default(balloonWindow4, 0, 0, 3, null);
                        }
                    } else if (iOrdinal == 4) {
                        BalloonWindow balloonWindow5 = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow5 != null) {
                            BalloonWindow.DefaultImpls.showAtCenter$default(balloonWindow5, 0, 0, null, 7, null);
                        }
                    } else {
                        if (iOrdinal != 5) {
                            throw new NoWhenBranchMatchedException();
                        }
                        BalloonWindow balloonWindow6 = (BalloonWindow) interfaceC0773a0.getValue();
                        if (balloonWindow6 != null) {
                            BalloonWindow.DefaultImpls.showAsDropDown$default(balloonWindow6, 0, 0, 3, null);
                        }
                    }
                }
                return Unit.a;
        }
    }

    public /* synthetic */ C1279l(boolean z, Object obj, Object obj2, int i) {
        this.a = i;
        this.b = z;
        this.c = obj;
        this.d = obj2;
    }
}
