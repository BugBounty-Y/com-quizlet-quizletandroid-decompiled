package com.quizlet.features.setpage.header.ui;

import android.content.Context;
import android.text.SpannableStringBuilder;
import android.text.SpannedString;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.core.P;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.W0;
import androidx.compose.ui.graphics.C0861v;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.v;
import androidx.lifecycle.J;
import androidx.navigation.D;
import androidx.navigation.E;
import androidx.navigation.H;
import androidx.navigation.L;
import androidx.recyclerview.widget.C1364f;
import androidx.recyclerview.widget.RecyclerView;
import com.comscore.streaming.EventType;
import com.features.flashcards.creatormarketing.h;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3161h6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.quizlet.data.model.C4170u0;
import com.quizlet.data.model.U0;
import com.quizlet.db.data.models.persisted.DBDiagramShape;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.diagrams.ui.DiagramJSBridge;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.eventlogger.model.AndroidEventPayload;
import com.quizlet.features.folders.composables.V;
import com.quizlet.features.settings.composables.j;
import com.quizlet.features.settings.composables.navigation.k;
import com.quizlet.features.settings.composables.navigation.l;
import com.quizlet.features.settings.composables.navigation.m;
import com.quizlet.features.settings.composables.navigation.n;
import com.quizlet.features.settings.composables.navigation.o;
import com.quizlet.features.settings.composables.navigation.q;
import com.quizlet.features.settings.composables.navigation.r;
import com.quizlet.features.settings.composables.navigation.u;
import com.quizlet.features.settings.composables.s;
import com.quizlet.features.settings.data.states.y;
import com.quizlet.features.settings.viewmodels.p;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Create;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import com.quizlet.quizletandroid.ui.library.data.C4659m;
import com.quizlet.quizletandroid.ui.login.UserBirthdayFragment;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.A;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.AbstractC4707c;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.B;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.i;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final /* synthetic */ class g implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ g(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b bVar;
        String strD;
        DBDiagramShape dBDiagramShapeA;
        int i = 22;
        int i2 = 6;
        int i3 = 10;
        int i4 = 5;
        int i5 = 0;
        int i6 = 3;
        int i7 = 1;
        Object obj2 = this.c;
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                v semantics = (v) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                t.e(semantics, ((com.quizlet.features.setpage.header.data.d) obj3).d.a((Context) obj2));
                return Unit.a;
            case 1:
                AndroidEventLog logUserActionAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logUserActionAndroidEvent, "$this$logUserActionAndroidEvent");
                logUserActionAndroidEvent.setUserAction("progress_tracking_v2_loaded");
                ((h) obj3).getClass();
                h.a(logUserActionAndroidEvent, (com.quizlet.features.setpage.progress.b) obj2);
                return Unit.a;
            case 2:
                ((Boolean) obj).booleanValue();
                ((Function1) obj3).invoke((DBStudySet) obj2);
                return Unit.a;
            case 3:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                j jVar = (j) obj2;
                if (((y) obj3).p) {
                    jVar.b.invoke(bool);
                } else {
                    jVar.a.invoke();
                }
                return Unit.a;
            case 4:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                androidx.compose.runtime.internal.j jVar2 = (androidx.compose.runtime.internal.j) obj2;
                y yVar = (y) obj3;
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -331603572, new s(yVar, jVar2, i5)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -1563254461, new s(yVar, jVar2, i7)), 3);
                if (yVar.o) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 803780967, new s(yVar, jVar2, 2)), 3);
                }
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -278191932, new s(yVar, jVar2, i6)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 1006870597, new s(yVar, jVar2, 4)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -2003034170, new com.quizlet.features.settings.composables.t(jVar2, i5)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, -717971641, new com.quizlet.features.settings.composables.t(jVar2, i7)), 3);
                androidx.compose.foundation.lazy.g.p(LazyColumn, null, new androidx.compose.runtime.internal.d(true, 567090888, new s(yVar, jVar2, i4)), 3);
                return Unit.a;
            case 5:
                E NavHost = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                p pVar = (p) obj2;
                H h = (H) obj3;
                N5.d(NavHost, com.quizlet.features.settings.composables.navigation.s.a, new androidx.compose.runtime.internal.d(true, 877923843, new com.quizlet.features.settings.composables.navigation.a(h, pVar, i6)));
                N5.d(NavHost, o.a, new androidx.compose.runtime.internal.d(true, 405932858, new com.quizlet.features.notes.detail.navigation.d(h, i6)));
                N5.e(NavHost, n.a, new androidx.compose.runtime.internal.d(true, -116308290, new com.quizlet.features.notes.detail.navigation.d(h, 4)));
                N5.d(NavHost, u.a, new androidx.compose.runtime.internal.d(true, 1569514043, new com.quizlet.features.notes.detail.navigation.d(h, i4)));
                N5.e(NavHost, com.quizlet.features.settings.composables.navigation.t.a, new androidx.compose.runtime.internal.d(true, -1568407243, new com.quizlet.features.notes.detail.navigation.d(h, i2)));
                N5.e(NavHost, com.quizlet.features.settings.composables.navigation.v.a, new androidx.compose.runtime.internal.d(true, -404826058, new com.quizlet.features.notes.detail.navigation.d(h, 7)));
                N5.d(NavHost, k.a, new androidx.compose.runtime.internal.d(true, -1561872068, new com.quizlet.features.notes.detail.navigation.d(h, 8)));
                N5.e(NavHost, com.quizlet.features.settings.composables.navigation.j.a, new androidx.compose.runtime.internal.d(true, 758755127, new com.quizlet.features.notes.detail.navigation.d(h, 9)));
                N5.d(NavHost, q.a, new androidx.compose.runtime.internal.d(true, -398290883, new com.quizlet.features.notes.detail.navigation.d(h, i3)));
                N5.e(NavHost, com.quizlet.features.settings.composables.navigation.p.a, new androidx.compose.runtime.internal.d(true, 1922336312, new com.quizlet.features.notes.detail.navigation.d(h, 2)));
                N5.d(NavHost, m.a, new androidx.compose.runtime.internal.d(true, 765290302, new com.quizlet.features.settings.composables.navigation.a(h, pVar, i5)));
                N5.e(NavHost, l.a, new androidx.compose.runtime.internal.d(true, -1209049799, new com.quizlet.features.settings.composables.navigation.a(h, pVar, i7)));
                N5.d(NavHost, r.a, new androidx.compose.runtime.internal.d(true, 1928871487, new com.quizlet.features.settings.composables.navigation.a(h, pVar, 2)));
                return Unit.a;
            case 6:
                androidx.compose.foundation.lazy.g LazyColumn2 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn2, "$this$LazyColumn");
                com.quizlet.features.universaluploadflow.flashcards.data.p pVar2 = (com.quizlet.features.universaluploadflow.flashcards.data.p) obj3;
                List list = pVar2.a;
                LazyColumn2.q(list.size(), null, new com.quizlet.assembly.compose.menu.e(list, 12), new androidx.compose.runtime.internal.d(true, -632812321, new V(list, (Object) pVar2, (Function1) obj2, 2)));
                return Unit.a;
            case 7:
                String it2 = (String) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                C4170u0 c4170u0 = U0.b;
                ((com.quizlet.features.universaluploadflow.navigation.e) obj3).g(it2);
                ((Function0) obj2).invoke();
                return Unit.a;
            case 8:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((InterfaceC0773a0) obj3).setValue(it3);
                ((InterfaceC0773a0) obj2).setValue(Boolean.valueOf(!StringsKt.O(it3)));
                return Unit.a;
            case 9:
                androidx.compose.ui.graphics.drawscope.d drawBehind = (androidx.compose.ui.graphics.drawscope.d) obj;
                Intrinsics.checkNotNullParameter(drawBehind, "$this$drawBehind");
                long j = ((C0861v) ((W0) obj3).getValue()).a;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.b();
                float f = com.quizlet.ui.resources.designsystem.generated.f.j;
                androidx.compose.ui.graphics.drawscope.d.z0(drawBehind, j, 0L, 0L, O4.a(f, f), null, 246);
                long j2 = ((C0861v) ((W0) obj2).getValue()).a;
                androidx.compose.ui.graphics.drawscope.h hVar = new androidx.compose.ui.graphics.drawscope.h(drawBehind.c0(com.quizlet.themes.m.l), DefinitionKt.NO_Float_VALUE, 0, 0, 30);
                mVar.b();
                androidx.compose.ui.graphics.drawscope.d.z0(drawBehind, j2, 0L, 0L, O4.a(f, f), hVar, 230);
                return Unit.a;
            case 10:
                DBUser u = (DBUser) obj;
                Intrinsics.checkNotNullParameter(u, "u");
                ((androidx.work.impl.model.c) obj3).getClass();
                Calendar calendar = Calendar.getInstance();
                Intrinsics.checkNotNullExpressionValue(calendar, "getInstance(...)");
                calendar.set(u.getBirthYear(), u.getBirthMonth(), u.getBirthDay());
                Calendar calendar2 = (Calendar) obj2;
                int i8 = calendar2.get(1) - calendar.get(1);
                if (calendar2.get(6) < calendar.get(6)) {
                    i8--;
                }
                return Integer.valueOf(i8);
            case 11:
                Boolean isLoggedIn = (Boolean) obj;
                Intrinsics.checkNotNullParameter(isLoggedIn, "isLoggedIn");
                AbstractActivityC0055k abstractActivityC0055k = (AbstractActivityC0055k) obj3;
                Intrinsics.checkNotNullParameter(abstractActivityC0055k, "<this>");
                if (!abstractActivityC0055k.isFinishing() && !abstractActivityC0055k.getSupportFragmentManager().R() && isLoggedIn.booleanValue() && !com.quizlet.features.consent.onetrust.a.b) {
                    ((com.quizlet.features.consent.onetrust.d) ((com.quizlet.quizletandroid.ui.base.g) obj2).p.get()).b(abstractActivityC0055k, null);
                }
                return Unit.a;
            case 12:
                L l = (L) obj;
                Intrinsics.checkNotNullParameter(l, "<this>");
                if (!Intrinsics.b((com.quizlet.quizletandroid.ui.globalnav.data.k) obj3, GlobalNavSuiteItem$Create.INSTANCE)) {
                    int i9 = D.g;
                    l.a(I1.f(((androidx.navigation.r) obj2).b.h()).b.c, new com.quizlet.quizletandroid.config.features.properties.d(i3));
                }
                l.b = true;
                l.c = true;
                return Unit.a;
            case 13:
                com.quizlet.quizletandroid.ui.globalnav.data.k it4 = (com.quizlet.quizletandroid.ui.globalnav.data.k) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                ((com.quizlet.quizletandroid.ui.globalnav.viewmodel.e) obj3).B(new com.quizlet.quizletandroid.ui.globalnav.data.m(it4));
                E4.g((H) obj2, it4);
                return Unit.a;
            case 14:
                int iIntValue = ((Integer) obj).intValue();
                com.quizlet.library.data.d dVar = (com.quizlet.library.data.d) ((androidx.paging.compose.d) obj3).b(iIntValue);
                if (dVar != null) {
                    ((Function1) obj2).invoke(new C4659m(iIntValue, dVar));
                }
                return Unit.a;
            case 15:
                androidx.compose.runtime.H DisposableEffect = (androidx.compose.runtime.H) obj;
                Intrinsics.checkNotNullParameter(DisposableEffect, "$this$DisposableEffect");
                androidx.emoji2.text.k kVar = new androidx.emoji2.text.k((InterfaceC4646d) obj2, i7);
                J j3 = (J) obj3;
                j3.getLifecycle().a(kVar);
                return new P(19, j3, kVar);
            case 16:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                String str = UserBirthdayFragment.w;
                UserBirthdayFragment userBirthdayFragment = (UserBirthdayFragment) obj3;
                if (userBirthdayFragment.W() && (zBooleanValue || userBirthdayFragment.X())) {
                    ((com.quizlet.quizletandroid.ui.globalnav.composable.n) obj2).invoke();
                }
                return Unit.a;
            case 17:
                com.quizlet.quizletandroid.ui.setcreation.navigation.e eVar = (com.quizlet.quizletandroid.ui.setcreation.navigation.e) obj;
                String str2 = EditSetFragment.J;
                EditSetFragment editSetFragment = (EditSetFragment) obj3;
                if (eVar instanceof com.quizlet.quizletandroid.ui.setcreation.navigation.b) {
                    String str3 = UpgradeActivity.v;
                    ((com.quizlet.quizletandroid.ui.setcreation.navigation.b) eVar).getClass();
                    editSetFragment.startActivityForResult(AbstractC3242q6.i((Context) obj2, "android_iap_source_rich_text_editor", com.quizlet.features.infra.models.upgrade.a.m), 101);
                } else if (eVar instanceof com.quizlet.quizletandroid.ui.setcreation.navigation.d) {
                    com.quizlet.quizletandroid.ui.setcreation.navigation.d dVar2 = (com.quizlet.quizletandroid.ui.setcreation.navigation.d) eVar;
                    Intrinsics.checkNotNullParameter("", "message");
                    String string = editSetFragment.getString(R.string.under_set_creation_dialog_confirm_now);
                    Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                    SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(string);
                    Context contextRequireContext = editSetFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                    androidx.compose.ui.text.font.m mVar2 = com.quizlet.ui.resources.designsystem.generated.a.a;
                    AbstractC3161h6.g(spannableStringBuilder, contextRequireContext, R.font.hurme_geometric_sans_2_bold);
                    String string2 = editSetFragment.getString(R.string.under_set_creation_dialog_description);
                    Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                    SpannedString message = com.quizlet.uicommon.util.a.a(string2, spannableStringBuilder);
                    Intrinsics.checkNotNullExpressionValue(message, "format(...)");
                    Intrinsics.checkNotNullParameter(message, "message");
                    com.quizlet.qutils.string.f fVar = dVar2.a;
                    Context contextRequireContext2 = editSetFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                    String title = AbstractC3053s1.e(fVar, contextRequireContext2);
                    Intrinsics.checkNotNullParameter(title, "title");
                    Context contextRequireContext3 = editSetFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext3, "requireContext(...)");
                    String text = AbstractC3053s1.e(dVar2.b, contextRequireContext3);
                    com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar2 = new com.quizlet.quizletandroid.ui.setcreation.fragments.b(dVar2, 0);
                    Intrinsics.checkNotNullParameter(text, "text");
                    Context contextRequireContext4 = editSetFragment.requireContext();
                    Intrinsics.checkNotNullExpressionValue(contextRequireContext4, "requireContext(...)");
                    String text2 = AbstractC3053s1.e(dVar2.c, contextRequireContext4).toUpperCase(Locale.ROOT);
                    Intrinsics.checkNotNullExpressionValue(text2, "toUpperCase(...)");
                    com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar3 = new com.quizlet.quizletandroid.ui.setcreation.fragments.b(dVar2, 1);
                    Intrinsics.checkNotNullParameter(text2, "text");
                    i iVar = new i(new QAlertDialogFragment.DialogData("", title, text, text2, false, message), bVar2, bVar3, null);
                    String str4 = QAlertDialogFragment.t;
                    com.quizlet.uicommon.ui.common.dialogs.h.a(iVar).O(editSetFragment.getChildFragmentManager(), QAlertDialogFragment.t);
                    com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVarC0 = editSetFragment.c0();
                    EventLoggerExt.c((EventLogger) eVarC0.g.b, new z(i2));
                    eVarC0.o.j(Unit.a);
                } else {
                    com.quizlet.quizletandroid.ui.setcreation.navigation.a aVar = com.quizlet.quizletandroid.ui.setcreation.navigation.a.a;
                    if (Intrinsics.b(eVar, aVar)) {
                        WeakReference weakReference = editSetFragment.x;
                        if (weakReference != null && (bVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.b) weakReference.get()) != null) {
                            ((com.quizlet.quizletandroid.ui.setcreation.activities.d) bVar).onBackPressed();
                        }
                    } else {
                        if (!(eVar instanceof com.quizlet.quizletandroid.ui.setcreation.navigation.c)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        com.quizlet.quizletandroid.ui.setcreation.navigation.c cVar = (com.quizlet.quizletandroid.ui.setcreation.navigation.c) eVar;
                        com.quizlet.quizletandroid.ui.webpages.a aVar2 = com.quizlet.quizletandroid.ui.webpages.a.a;
                        Context contextRequireContext5 = editSetFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext5, "requireContext(...)");
                        cVar.getClass();
                        Context contextRequireContext6 = editSetFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext6, "requireContext(...)");
                        aVar2.b(contextRequireContext5, "https://help.quizlet.com/hc/articles/360029190271", AbstractC3053s1.e(cVar.a, contextRequireContext6));
                        editSetFragment.c0().l.j(aVar);
                    }
                }
                return Unit.a;
            case 18:
                RecyclerView it5 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g gVar = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.h) obj3).d;
                it5.setAdapter(gVar);
                gVar.f(((com.quizlet.quizletandroid.ui.startpage.nav2.model.z) obj2).d);
                return Unit.a;
            case 19:
                RecyclerView it6 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.i iVar2 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.j) obj3).d;
                it6.setAdapter(iVar2);
                iVar2.f(((A) obj2).d);
                return Unit.a;
            case 20:
                RecyclerView it7 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g gVar2 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.k) obj3).d;
                it7.setAdapter(gVar2);
                ((C1364f) gVar2.b).b(((com.quizlet.quizletandroid.ui.startpage.nav2.model.y) obj2).d, new com.google.firebase.crashlytics.internal.metadata.q(it7, i));
                return Unit.a;
            case 21:
                RecyclerView it8 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.g gVar3 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.l) obj3).d;
                it8.setAdapter(gVar3);
                gVar3.f(((B) obj2).d);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                RecyclerView it9 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r rVar = (com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r) obj3;
                it9.setAdapter(rVar);
                rVar.f(((C) ((AbstractC4707c) obj2)).g());
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                RecyclerView it10 = (RecyclerView) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                com.quizlet.quizletandroid.ui.startpage.nav2.adapters.r rVar2 = ((com.quizlet.quizletandroid.ui.startpage.nav2.adapters.q) obj3).d;
                it10.setAdapter(rVar2);
                rVar2.f(((com.quizlet.quizletandroid.ui.startpage.nav2.model.E) obj2).d);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                AndroidEventPayload payload = logAndroidEvent.getPayload();
                List<com.quizlet.ui.models.content.home.f> list2 = (List) obj3;
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list2, 10));
                for (com.quizlet.ui.models.content.home.f fVar2 : list2) {
                    ((com.quizlet.quizletandroid.ui.startpage.nav2.logging.a) obj2).getClass();
                    if (Intrinsics.b(fVar2, com.quizlet.ui.models.content.home.a.c)) {
                        strD = "EmptyCardCourses";
                    } else if (Intrinsics.b(fVar2, com.quizlet.ui.models.content.home.b.c)) {
                        strD = "EmptyCardFlashcards";
                    } else if (Intrinsics.b(fVar2, com.quizlet.ui.models.content.home.e.c)) {
                        strD = "EmptyCardSearch";
                    } else if (Intrinsics.b(fVar2, com.quizlet.ui.models.content.home.c.c)) {
                        strD = "EmptyCardMagicNotes";
                    } else {
                        if (!(fVar2 instanceof com.quizlet.ui.models.content.home.d)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        strD = AbstractC0147y.d("EmptyCardRevisionCenter-", ((com.quizlet.ui.models.content.home.d) fVar2).c.a());
                    }
                    arrayList.add(strD);
                }
                payload.setGetStartedItems(arrayList);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                androidx.compose.foundation.lazy.g LazyColumn3 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn3, "$this$LazyColumn");
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n nVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.n) obj3;
                androidx.compose.foundation.lazy.g.p(LazyColumn3, null, new androidx.compose.runtime.internal.d(true, 371986951, new com.quizlet.baseui.base.d(nVar, 14)), 3);
                List list3 = nVar.l;
                LazyColumn3.q(list3.size(), null, new com.quizlet.assembly.compose.menu.e(list3, 16), new androidx.compose.runtime.internal.d(true, -632812321, new V(list3, (Object) nVar, (Function1) obj2, i6)));
                return Unit.a;
            case EventType.CDN /* 26 */:
                androidx.compose.foundation.lazy.g LazyColumn4 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn4, "$this$LazyColumn");
                androidx.compose.foundation.lazy.g.p(LazyColumn4, null, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.composables.b.a, 3);
                com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p pVar3 = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.data.p) obj3;
                List list4 = pVar3.b;
                LazyColumn4.q(list4.size(), null, new com.quizlet.assembly.compose.menu.e(list4, 18), new androidx.compose.runtime.internal.d(true, -632812321, new V(list4, (Object) pVar3, (Function1) obj2, i4)));
                return Unit.a;
            case 27:
                DiagramJSBridge bridge = (DiagramJSBridge) obj;
                Intrinsics.checkNotNullParameter(bridge, "bridge");
                com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f fVar3 = (com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f) obj3;
                if (!com.bumptech.glide.b.c(fVar3.a ? 1 : 0) && (dBDiagramShapeA = fVar3.a()) != null) {
                    bridge.b(dBDiagramShapeA.getTermId());
                }
                DBDiagramShape dBDiagramShapeA2 = ((com.quizlet.quizletandroid.ui.studymodes.testmode.studyengine.f) obj2).a();
                if (dBDiagramShapeA2 != null) {
                    bridge.a(dBDiagramShapeA2.getTermId());
                }
                return Unit.a;
            case 28:
                com.quizlet.uicommon.ui.common.util.d it11 = (com.quizlet.uicommon.ui.common.util.d) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                ((com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.t) obj3).B(it11, (ArrayList) obj2);
                return Unit.a;
            default:
                androidx.compose.foundation.lazy.g LazyColumn5 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn5, "$this$LazyColumn");
                kotlinx.collections.immutable.b bVar4 = ((com.quizlet.quizletandroid.ui.subject.viewmodel.g) obj3).d;
                LazyColumn5.q(bVar4.size(), null, new com.quizlet.assembly.compose.menu.e(bVar4, i), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.features.infra.folder.create.coursefolder.composable.m(bVar4, (Function1) obj2, i6)));
                androidx.compose.foundation.lazy.g.p(LazyColumn5, null, com.quizlet.quizletandroid.ui.subject.b.a, 3);
                return Unit.a;
        }
    }
}
