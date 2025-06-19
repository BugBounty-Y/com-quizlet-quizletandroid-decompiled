package com.quizlet.login.common.navigation;

import androidx.lifecycle.p0;
import androidx.navigation.B;
import androidx.navigation.H;
import androidx.navigation.compose.x;
import com.braze.events.ContentCardsUpdatedEvent;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3681n4;
import com.quizlet.data.model.EnumC4167t0;
import com.quizlet.eventlogger.EventLoggerExt;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.quizlet.login.signup.data.PromptParentEmailData;
import com.quizlet.login.signup.data.p;
import com.quizlet.login.signup.data.r;
import com.quizlet.quizletandroid.ui.base.ViewModelDataSourceRecyclerViewFragment;
import com.quizlet.quizletandroid.ui.globalnav.data.o;
import java.util.ArrayList;
import java.util.List;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class d extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        s0 s0Var;
        Object value;
        switch (this.a) {
            case 0:
                com.quizlet.ui.models.webpage.m webPage = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(webPage, "p0");
                com.quizlet.quizletandroid.ui.navigationmanagers.d dVar = (com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver;
                dVar.getClass();
                Intrinsics.checkNotNullParameter(webPage, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(dVar.a, webPage);
                return Unit.a;
            case 1:
                PromptParentEmailData promptParentEmailData = (PromptParentEmailData) obj;
                Intrinsics.checkNotNullParameter(promptParentEmailData, "p0");
                H h = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                Intrinsics.checkNotNullParameter(promptParentEmailData, "promptParentEmailData");
                B bK = h.b.h().k("parent_email");
                if (bK != null) {
                    h.b(bK.b.c, AbstractC3206m6.a(new Pair("parentEmailData", promptParentEmailData)), J1.c(new C4566c0(16)));
                }
                return Unit.a;
            case 2:
                String p0 = (String) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                e.d((H) this.receiver, p0);
                return Unit.a;
            case 3:
                String p02 = (String) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                e.c((H) this.receiver, p02);
                return Unit.a;
            case 4:
                com.quizlet.ui.models.webpage.m webPage2 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(webPage2, "p0");
                com.quizlet.quizletandroid.ui.navigationmanagers.d dVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver;
                dVar2.getClass();
                Intrinsics.checkNotNullParameter(webPage2, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(dVar2.a, webPage2);
                return Unit.a;
            case 5:
                String p03 = (String) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                e.d((H) this.receiver, p03);
                return Unit.a;
            case 6:
                String p04 = (String) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                e.c((H) this.receiver, p04);
                return Unit.a;
            case 7:
                com.quizlet.login.intro.data.j p05 = (com.quizlet.login.intro.data.j) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                ((com.quizlet.login.intro.viewmodel.e) ((com.quizlet.login.intro.viewmodel.a) this.receiver)).C(p05);
                return Unit.a;
            case 8:
                com.quizlet.login.login.data.k p06 = (com.quizlet.login.login.data.k) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                ((com.quizlet.login.login.viewmodel.f) ((com.quizlet.login.login.viewmodel.a) this.receiver)).E(p06);
                return Unit.a;
            case 9:
                String email = (String) obj;
                Intrinsics.checkNotNullParameter(email, "p0");
                com.quizlet.login.magiclink.viewmodel.j jVar = (com.quizlet.login.magiclink.viewmodel.j) ((com.quizlet.login.magiclink.viewmodel.b) this.receiver);
                jVar.getClass();
                Intrinsics.checkNotNullParameter(email, "email");
                E.A(p0.j(jVar), null, null, new com.quizlet.login.magiclink.viewmodel.i(jVar, email, null), 3);
                return Unit.a;
            case 10:
                EnumC4167t0 p07 = (EnumC4167t0) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                ((com.quizlet.login.magiclink.viewmodel.g) this.receiver).v(p07);
                return Unit.a;
            case 11:
                com.quizlet.login.parentemail.data.f event = (com.quizlet.login.parentemail.data.f) obj;
                Intrinsics.checkNotNullParameter(event, "p0");
                com.quizlet.login.parentemail.viewmodel.e eVar = (com.quizlet.login.parentemail.viewmodel.e) ((com.quizlet.login.parentemail.viewmodel.a) this.receiver);
                eVar.getClass();
                Intrinsics.checkNotNullParameter(event, "event");
                boolean zB = Intrinsics.b(event, com.quizlet.login.parentemail.data.a.a);
                d0 d0Var = eVar.e;
                if (zB) {
                    d0Var.h(com.quizlet.login.parentemail.data.g.a);
                } else if (event instanceof com.quizlet.login.parentemail.data.b) {
                    com.quizlet.login.parentemail.data.b bVar = (com.quizlet.login.parentemail.data.b) event;
                    E.A(p0.j(eVar), null, null, new com.quizlet.login.parentemail.viewmodel.b(eVar, bVar.a, bVar.b, null), 3);
                } else if (Intrinsics.b(event, com.quizlet.login.parentemail.data.e.a)) {
                    d0Var.h(new com.quizlet.login.parentemail.data.m(com.quizlet.ui.models.webpage.l.c));
                } else if (Intrinsics.b(event, com.quizlet.login.parentemail.data.d.a)) {
                    d0Var.h(new com.quizlet.login.parentemail.data.m(com.quizlet.ui.models.webpage.i.c));
                } else {
                    if (!(event instanceof com.quizlet.login.parentemail.data.c)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    E.A(p0.j(eVar), null, null, new com.quizlet.login.parentemail.viewmodel.c(eVar, ((com.quizlet.login.parentemail.data.c) event).a, null), 3);
                }
                return Unit.a;
            case 12:
                com.quizlet.login.resetpassword.data.c event2 = (com.quizlet.login.resetpassword.data.c) obj;
                Intrinsics.checkNotNullParameter(event2, "p0");
                com.quizlet.login.resetpassword.viewmodel.c cVar = (com.quizlet.login.resetpassword.viewmodel.c) ((com.quizlet.login.resetpassword.viewmodel.a) this.receiver);
                cVar.getClass();
                Intrinsics.checkNotNullParameter(event2, "event");
                if (Intrinsics.b(event2, com.quizlet.login.resetpassword.data.a.a)) {
                    cVar.d.h(com.quizlet.login.resetpassword.data.d.a);
                } else {
                    if (!(event2 instanceof com.quizlet.login.resetpassword.data.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    String str = ((com.quizlet.login.resetpassword.data.b) event2).a;
                    if (!StringsKt.O(str)) {
                        E.A(p0.j(cVar), null, null, new com.quizlet.login.resetpassword.viewmodel.b(cVar, str, null), 3);
                    }
                }
                return Unit.a;
            case 13:
                com.quizlet.login.signup.data.h event3 = (com.quizlet.login.signup.data.h) obj;
                Intrinsics.checkNotNullParameter(event3, "p0");
                com.quizlet.login.signup.viewmodel.g gVar = (com.quizlet.login.signup.viewmodel.g) ((com.quizlet.login.signup.viewmodel.a) this.receiver);
                gVar.getClass();
                Intrinsics.checkNotNullParameter(event3, "event");
                if (event3 instanceof com.quizlet.login.signup.data.c) {
                    com.quizlet.login.signup.data.c cVar2 = (com.quizlet.login.signup.data.c) event3;
                    long j = cVar2.a;
                    EventLoggerExt.c(gVar.b.a, new com.quizlet.quizletandroid.config.features.properties.d(29));
                    E.A(p0.j(gVar), null, null, new com.quizlet.login.signup.viewmodel.c(gVar, cVar2.b, cVar2.c, j, cVar2.d, null), 3);
                } else {
                    boolean zB2 = Intrinsics.b(event3, com.quizlet.login.signup.data.a.a);
                    d0 d0Var2 = gVar.h;
                    if (zB2) {
                        d0Var2.h(com.quizlet.login.signup.data.i.a);
                    } else if (Intrinsics.b(event3, com.quizlet.login.signup.data.f.a)) {
                        d0Var2.h(new p(com.quizlet.ui.models.webpage.i.c));
                    } else if (Intrinsics.b(event3, com.quizlet.login.signup.data.g.a)) {
                        d0Var2.h(new p(com.quizlet.ui.models.webpage.l.c));
                    } else if (Intrinsics.b(event3, com.quizlet.login.signup.data.b.a)) {
                        do {
                            s0Var = gVar.g;
                            value = s0Var.getValue();
                        } while (!s0Var.k(value, r.a((r) value, false, false, null, com.quizlet.login.common.interactors.data.f.a, null, 47)));
                    } else if (event3 instanceof com.quizlet.login.signup.data.d) {
                        E.A(p0.j(gVar), null, null, new com.quizlet.login.signup.viewmodel.d(gVar, ((com.quizlet.login.signup.data.d) event3).a, null), 3);
                    } else {
                        if (!(event3 instanceof com.quizlet.login.signup.data.e)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        E.A(p0.j(gVar), null, null, new com.quizlet.login.signup.viewmodel.e(gVar, ((com.quizlet.login.signup.data.e) event3).a, null), 3);
                    }
                }
                return Unit.a;
            case 14:
                com.quizlet.features.infra.snackbar.l p08 = (com.quizlet.features.infra.snackbar.l) obj;
                Intrinsics.checkNotNullParameter(p08, "p0");
                ((com.quizlet.features.infra.snackbar.viewmodel.c) ((com.quizlet.features.infra.snackbar.viewmodel.a) this.receiver)).A(p08);
                return Unit.a;
            case 15:
                ContentCardsUpdatedEvent event4 = (ContentCardsUpdatedEvent) obj;
                Intrinsics.checkNotNullParameter(event4, "p0");
                com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a aVar = (com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) this.receiver;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(event4, "event");
                ArrayList arrayListB = AbstractC3681n4.b(event4.getAllCards());
                aVar.d.n(arrayListB);
                ArrayList arrayListY0 = CollectionsKt.y0(CollectionsKt.n0(arrayListB, new androidx.camera.core.internal.compat.workaround.a(new x(17), 3)));
                ArrayList arrayList = aVar.j;
                arrayList.clear();
                arrayList.addAll(arrayListY0);
                return arrayListY0;
            case 16:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 17:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 18:
                List p09 = (List) obj;
                Intrinsics.checkNotNullParameter(p09, "p0");
                ((ViewModelDataSourceRecyclerViewFragment) this.receiver).W(p09);
                return Unit.a;
            case 19:
                ((ViewModelDataSourceRecyclerViewFragment) this.receiver).l.c(((Boolean) obj).booleanValue());
                return Unit.a;
            case 20:
                ((timber.log.a) this.receiver).e((Throwable) obj);
                return Unit.a;
            case 21:
                com.quizlet.infra.legacysyncengine.net.request.c p010 = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                Intrinsics.checkNotNullParameter(p010, "p0");
                com.quizlet.quizletandroid.ui.base.viewmodel.a aVar2 = (com.quizlet.quizletandroid.ui.base.viewmodel.a) this.receiver;
                aVar2.e.j(Boolean.FALSE);
                aVar2.f.j(p010);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                o p011 = (o) obj;
                Intrinsics.checkNotNullParameter(p011, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.viewmodel.e) this.receiver).B(p011);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                String p012 = (String) obj;
                Intrinsics.checkNotNullParameter(p012, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).A(p012);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                String p013 = (String) obj;
                Intrinsics.checkNotNullParameter(p013, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).p(p013);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).v(((Number) obj).longValue());
                return Unit.a;
            case EventType.CDN /* 26 */:
                String p014 = (String) obj;
                Intrinsics.checkNotNullParameter(p014, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).k(p014);
                return Unit.a;
            case 27:
                String p015 = (String) obj;
                Intrinsics.checkNotNullParameter(p015, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).n(p015);
                return Unit.a;
            case 28:
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).z(((Number) obj).longValue());
                return Unit.a;
            default:
                String p016 = (String) obj;
                Intrinsics.checkNotNullParameter(p016, "p0");
                ((com.quizlet.quizletandroid.ui.globalnav.navigation.a) this.receiver).l(p016);
                return Unit.a;
        }
    }
}
