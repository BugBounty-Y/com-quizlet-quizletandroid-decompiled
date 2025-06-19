package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.cardview.widget.CardView;
import androidx.compose.material3.C0676l1;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.paging.AbstractC1348x;
import androidx.paging.C1347w0;
import androidx.paging.V;
import androidx.recyclerview.widget.RecyclerView;
import androidx.work.P;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.X5;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.eventlogger.model.LibraryEventLog;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.partskit.widgets.QRadioButton;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4611o;
import com.quizlet.quizletandroid.ui.group.classcontent.ClassContentListFragment;
import com.quizlet.quizletandroid.ui.library.InterfaceC4646d;
import com.quizlet.quizletandroid.ui.library.Q;
import com.quizlet.quizletandroid.ui.library.S;
import com.quizlet.quizletandroid.ui.library.T;
import com.quizlet.quizletandroid.ui.library.U;
import com.quizlet.quizletandroid.ui.library.c0;
import com.quizlet.quizletandroid.ui.login.UserBirthdayFragment;
import com.quizlet.quizletandroid.ui.login.z;
import com.quizlet.quizletandroid.ui.startpage.nav2.OldHomeFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4734c;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4735d;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4736e;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4737f;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4739h;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.C4749s;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.G;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.UUID;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class n extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ n(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    /* JADX WARN: Type inference failed for: r4v9, types: [io.reactivex.rxjava3.disposables.b, java.util.concurrent.atomic.AtomicReference] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        s0 s0Var;
        Object value;
        com.quizlet.quizletandroid.ui.login.viewmodels.a aVar = com.quizlet.quizletandroid.ui.login.viewmodels.a.a;
        int i = 2;
        int i2 = 8;
        switch (this.a) {
            case 0:
                L l = (L) this.receiver;
                l.getClass();
                E.A(p0.j(l), null, null, new G(l, null), 3);
                return Unit.a;
            case 1:
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).m();
                return Unit.a;
            case 2:
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).getClass();
                return Unit.a;
            case 3:
                ClassContentListFragment classContentListFragment = (ClassContentListFragment) this.receiver;
                String str = ClassContentListFragment.n;
                ((C4611o) classContentListFragment.J()).b.setVisibility(0);
                ((C4611o) classContentListFragment.J()).c.setVisibility(8);
                CardView cardView = classContentListFragment.m;
                if (cardView != null) {
                    cardView.setVisibility(8);
                }
                return Unit.a;
            case 4:
                com.quizlet.library.viewmodels.d dVar = (com.quizlet.library.viewmodels.d) ((com.quizlet.library.viewmodels.c) this.receiver);
                if (dVar.e == null) {
                    C0676l1 config = new C0676l1(20, 60);
                    com.quizlet.featuregate.growthbook.a pagingSourceFactory = new com.quizlet.featuregate.growthbook.a(dVar, 25);
                    Intrinsics.checkNotNullParameter(config, "config");
                    Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
                    Intrinsics.checkNotNullParameter(config, "config");
                    Intrinsics.checkNotNullParameter(pagingSourceFactory, "pagingSourceFactory");
                    dVar.e = AbstractC1348x.b(new V(new C1347w0(pagingSourceFactory, null), config).e, p0.j(dVar));
                }
                Y y = dVar.e;
                if (y != null) {
                    return y;
                }
                throw new IllegalArgumentException("Pager must be not null");
            case 5:
                c0 c0Var = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar = c0Var.i;
                bVar.getClass();
                bVar.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_create_set", new com.quizlet.features.universaluploadflow.flashcards.d(16), 6));
                E.A(p0.j(c0Var), null, null, new com.quizlet.quizletandroid.ui.library.V(c0Var, null), 3);
                return Unit.a;
            case 6:
                c0 c0Var2 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar2 = c0Var2.i;
                bVar2.getClass();
                bVar2.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "your_library_empty_state_start_generating_button_clicked", new com.quizlet.features.universaluploadflow.flashcards.d(11), 6));
                E.A(p0.j(c0Var2), null, null, new U(c0Var2, null), 3);
                return Unit.a;
            case 7:
                c0 c0Var3 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar3 = c0Var3.i;
                bVar3.getClass();
                bVar3.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_create_class", new com.quizlet.features.universaluploadflow.flashcards.d(15), 6));
                E.A(p0.j(c0Var3), null, null, new Q(c0Var3, null), 3);
                return Unit.a;
            case 8:
                c0 c0Var4 = (c0) ((InterfaceC4646d) this.receiver);
                com.quizlet.library.logging.b bVar4 = c0Var4.i;
                bVar4.getClass();
                bVar4.a(LibraryEventLog.Companion.a(LibraryEventLog.b, "clicked_create_folder", new com.quizlet.features.universaluploadflow.flashcards.d(19), 6));
                E.A(p0.j(c0Var4), null, null, new S(c0Var4, null), 3);
                return Unit.a;
            case 9:
                c0 c0Var5 = (c0) ((InterfaceC4646d) this.receiver);
                c0Var5.getClass();
                E.A(p0.j(c0Var5), null, null, new T(c0Var5, null), 3);
                return Unit.a;
            case 10:
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                fVar.j.dispose();
                do {
                    s0Var = fVar.h;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value, aVar, null, 2)));
                return Unit.a;
            case 11:
                int i3 = 1;
                com.quizlet.quizletandroid.ui.login.viewmodels.f fVar2 = (com.quizlet.quizletandroid.ui.login.viewmodels.f) this.receiver;
                while (true) {
                    s0 s0Var2 = fVar2.h;
                    Object value2 = s0Var2.getValue();
                    int i4 = i3;
                    if (s0Var2.k(value2, com.quizlet.quizletandroid.ui.login.viewmodels.h.a((com.quizlet.quizletandroid.ui.login.viewmodels.h) value2, null, aVar, i4))) {
                        return Unit.a;
                    }
                    i3 = i4;
                }
            case 12:
                UserBirthdayFragment userBirthdayFragment = (UserBirthdayFragment) this.receiver;
                String str2 = UserBirthdayFragment.w;
                int year = userBirthdayFragment.Q().getYear();
                com.quizlet.time.c month = userBirthdayFragment.Q().getMonth();
                int day = userBirthdayFragment.Q().getDay();
                String strValueOf = String.valueOf(userBirthdayFragment.R().getText());
                QRadioButton teacherYes = (QRadioButton) userBirthdayFragment.T().c;
                Intrinsics.checkNotNullExpressionValue(teacherYes, "teacherYes");
                boolean zIsChecked = teacherYes.isChecked();
                if (!P.e(year, month, day, 22)) {
                    i = 0;
                } else if (zIsChecked) {
                    i = 1;
                }
                final com.quizlet.login.oldlogin.o oVar = (com.quizlet.login.oldlogin.o) userBirthdayFragment.m.getValue();
                String oauthToken = userBirthdayFragment.requireArguments().getString("oauthToken", "");
                Intrinsics.checkNotNullExpressionValue(oauthToken, "<get-oauthToken>(...)");
                int i5 = month.a;
                int i6 = i5 + 1;
                com.quizlet.time.a birthMonth = new com.quizlet.time.a(i6);
                final boolean z = userBirthdayFragment.requireArguments().getBoolean("isSignUp", false);
                final String authProvider = userBirthdayFragment.requireArguments().getString("authProvider", "");
                Intrinsics.checkNotNullExpressionValue(authProvider, "<get-authProvider>(...)");
                oVar.getClass();
                Intrinsics.checkNotNullParameter(oauthToken, "oauthToken");
                Intrinsics.checkNotNullParameter(birthMonth, "birthMonth");
                Intrinsics.checkNotNullParameter(authProvider, "authProvider");
                final LinkedHashMap linkedHashMapG = kotlin.collections.V.g(new Pair("birthYear", String.valueOf(year)), new Pair("birthMonth", String.valueOf(i6)), new Pair("birthDay", String.valueOf(day)), new Pair("data", oauthToken), new Pair("isFreeTeacher", String.valueOf(i)), new Pair("state", UUID.randomUUID().toString()));
                linkedHashMapG.put("email", strValueOf);
                int iB = ((com.quizlet.quizletandroid.managers.g) oVar.i).b();
                GregorianCalendar gregorianCalendar = new GregorianCalendar();
                GregorianCalendar gregorianCalendar2 = new GregorianCalendar(year + iB, i5, day);
                final boolean z2 = !(gregorianCalendar2.before(gregorianCalendar) || gregorianCalendar2.equals(gregorianCalendar));
                io.reactivex.rxjava3.internal.observers.e eVarB = B7.b(oVar.h.r(), io.reactivex.rxjava3.kotlin.c.b, new Function1() { // from class: com.quizlet.login.oldlogin.g
                    @Override // kotlin.jvm.functions.Function1
                    public final Object invoke(Object obj) {
                        boolean zBooleanValue = ((Boolean) obj).booleanValue();
                        LinkedHashMap linkedHashMap = linkedHashMapG;
                        o oVar2 = oVar;
                        String authProvider2 = authProvider;
                        boolean z3 = z;
                        if (zBooleanValue && z2) {
                            linkedHashMap.remove("email");
                            b bVar5 = b.a;
                            com.google.android.gms.internal.appset.e eVar = oVar2.f;
                            eVar.getClass();
                            Intrinsics.checkNotNullParameter(authProvider2, "authProvider");
                            EventLoggerExt.a((EventLogger) eVar.b, "authentication_parent_email_request", new com.quizlet.features.notes.logging.b(authProvider2, z3));
                            oVar2.t.j(new LaunchParentEmailFragment(linkedHashMap, authProvider2, bVar5));
                        } else {
                            oVar2.C(linkedHashMap, z3, authProvider2);
                        }
                        return Unit.a;
                    }
                });
                Intrinsics.checkNotNullParameter(eVarB, "<this>");
                oVar.A(eVarB);
                return Unit.a;
            case 13:
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVar = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.e) this.receiver;
                EventLoggerExt.c((EventLogger) eVar.g.b, new z(7));
                Object[] args = new Object[0];
                Intrinsics.checkNotNullParameter(args, "args");
                eVar.l.j(new com.quizlet.quizletandroid.ui.setcreation.navigation.c(new com.quizlet.qutils.string.f(R.string.user_settings_help_center, C4933y.P(args))));
                return Unit.a;
            case 14:
                com.quizlet.quizletandroid.ui.setcreation.viewmodels.e eVar2 = (com.quizlet.quizletandroid.ui.setcreation.viewmodels.e) this.receiver;
                EventLoggerExt.c((EventLogger) eVar2.g.b, new z(i2));
                eVar2.l.j(com.quizlet.quizletandroid.ui.setcreation.navigation.a.a);
                return Unit.a;
            case 15:
                OldHomeFragment oldHomeFragment = (OldHomeFragment) this.receiver;
                String str3 = OldHomeFragment.d1;
                RecyclerView recyclerViewX = oldHomeFragment.X();
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y2 = oldHomeFragment.t;
                if (y2 != null) {
                    X5.b(recyclerViewX, y2, false, null, -1);
                    return Unit.a;
                }
                Intrinsics.m("viewModel");
                throw null;
            case 16:
                ((L) this.receiver).p.h(C4749s.a);
                return Unit.a;
            case 17:
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y3 = (com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.receiver;
                y3.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.h.a);
                y3.v.a("clicked_get_started_magic_notes", "get_started");
                return Unit.a;
            case 18:
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y4 = (com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.receiver;
                y4.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.c.a);
                y4.u.a();
                y4.v.a("clicked_get_started_add_course", "get_started");
                return Unit.a;
            case 19:
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y5 = (com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.receiver;
                y5.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.g.a);
                y5.v.a("clicked_get_started_create_set", "get_started");
                return Unit.a;
            case 20:
                com.quizlet.quizletandroid.ui.startpage.nav2.Y y6 = (com.quizlet.quizletandroid.ui.startpage.nav2.Y) this.receiver;
                y6.v.a("clicked_get_started_search", "get_started");
                y6.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.e.a);
                return Unit.a;
            case 21:
                C4739h c4739h = (C4739h) this.receiver;
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar = c4739h.e;
                cVar.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar, "clicked_create_set");
                E.A(p0.j(c4739h), null, null, new C4735d(c4739h, null), 3);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                C4739h c4739h2 = (C4739h) this.receiver;
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar2 = c4739h2.e;
                cVar2.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar2, "clicked_create_class");
                E.A(p0.j(c4739h2), null, null, new C4734c(c4739h2, null), 3);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                C4739h c4739h3 = (C4739h) this.receiver;
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar3 = c4739h3.e;
                cVar3.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar3, "clicked_create_folder");
                E.A(p0.j(c4739h3), null, null, new C4736e(c4739h3, null), 3);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                C4739h c4739h4 = (C4739h) this.receiver;
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c cVar4 = c4739h4.e;
                cVar4.getClass();
                com.quizlet.quizletandroid.ui.startpage.nav2.logging.c.a(cVar4, "clicked_create_practice_test");
                E.A(p0.j(c4739h4), null, null, new C4737f(c4739h4, null), 3);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                ((com.quizlet.learn.viewmodel.G) this.receiver).S();
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.quizlet.learn.viewmodel.G g = (com.quizlet.learn.viewmodel.G) this.receiver;
                String str4 = g.Z.t;
                m0 m0Var = g.d;
                Object objA = m0Var.a("studyableModelData");
                if (objA == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                StudyableModelData studyableModelData = (StudyableModelData) objA;
                Object objA2 = m0Var.a("studyableModelLocalId");
                if (objA2 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                long jLongValue = ((Number) objA2).longValue();
                Object objA3 = m0Var.a("selectedOnlyIntent");
                if (objA3 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                boolean zBooleanValue = ((Boolean) objA3).booleanValue();
                Object objA4 = m0Var.a("screen_name_key");
                if (objA4 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                String str5 = (String) objA4;
                Object objA5 = m0Var.a("navigationSource");
                if (objA5 == null) {
                    throw new IllegalArgumentException("Required value was null.");
                }
                g.M.j(new com.quizlet.learn.data.E(str4, studyableModelData, jLongValue, zBooleanValue, str5, ((Number) objA5).intValue(), g.E.isEnabled() && g.F.isEnabled()));
                return Unit.a;
            case 27:
                ((com.quizlet.learn.viewmodel.G) this.receiver).X();
                return Unit.a;
            case 28:
                ((com.quizlet.learn.viewmodel.G) this.receiver).D();
                return Unit.a;
            default:
                ((com.quizlet.learn.viewmodel.G) this.receiver).V();
                return Unit.a;
        }
    }
}
