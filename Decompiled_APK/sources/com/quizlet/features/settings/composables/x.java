package com.quizlet.features.settings.composables;

import android.content.Context;
import androidx.lifecycle.p0;
import androidx.navigation.B;
import androidx.navigation.H;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.J1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.A4;
import com.quizlet.api.model.ServerProvidedError;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.settings.viewmodels.C4444b;
import com.quizlet.features.settings.viewmodels.C4446d;
import com.quizlet.features.settings.viewmodels.F;
import com.quizlet.features.settings.viewmodels.G;
import com.quizlet.features.settings.viewmodels.I;
import com.quizlet.features.universaluploadflow.data.C4457f;
import com.quizlet.features.universaluploadflow.data.C4459h;
import com.quizlet.learn.data.D;
import com.quizlet.learn.viewmodel.A;
import com.quizlet.quizletandroid.ui.deeplinkinterstitial.DeepLinkInterstitialActivity;
import java.util.Collection;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final /* synthetic */ class x extends C4956o implements Function1 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ x(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        com.quizlet.features.settings.data.models.g gVar;
        s0 s0Var;
        Object value;
        s0 s0Var2;
        Object value2;
        int i = 3;
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                I i2 = (I) ((com.quizlet.features.settings.viewmodels.p) this.receiver);
                i2.h.a.I("toggle_autodownload_setting");
                i2.e.a.edit().putBoolean("PREF_OFFLINE_TOGGLE", zBooleanValue).apply();
                E.A(p0.j(i2), null, null, new F(i2, null), 3);
                break;
            case 1:
                boolean zBooleanValue2 = ((Boolean) obj).booleanValue();
                I i3 = (I) ((com.quizlet.features.settings.viewmodels.p) this.receiver);
                i3.h.a.I("user_settings_change_notifications_toggle");
                com.quizlet.quizletandroid.interactor.t tVar = i3.b;
                tVar.d.b(zBooleanValue2);
                DBUser dBUser = tVar.a.r;
                if (dBUser != null) {
                    dBUser.setSrsPushNotificationsEnabled(zBooleanValue2);
                    tVar.c.a(dBUser);
                }
                while (true) {
                    s0 s0Var3 = i3.n;
                    Object value3 = s0Var3.getValue();
                    I i4 = i3;
                    if (s0Var3.k(value3, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value3, null, null, false, false, null, null, null, null, zBooleanValue2, false, null, false, 7935))) {
                        break;
                    } else {
                        i3 = i4;
                    }
                }
            case 2:
                boolean zBooleanValue3 = ((Boolean) obj).booleanValue();
                I i5 = (I) ((com.quizlet.features.settings.viewmodels.p) this.receiver);
                while (true) {
                    s0 s0Var4 = i5.n;
                    Object value4 = s0Var4.getValue();
                    boolean z = zBooleanValue3;
                    if (s0Var4.k(value4, com.quizlet.features.settings.data.states.y.a((com.quizlet.features.settings.data.states.y) value4, null, null, false, false, null, null, null, null, false, zBooleanValue3, null, false, 7679))) {
                        E.A(p0.j(i5), null, null, new G(i5, z, null), 3);
                        break;
                    } else {
                        zBooleanValue3 = z;
                    }
                }
            case 3:
                com.quizlet.themes.nighttheme.a p0 = (com.quizlet.themes.nighttheme.a) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                ((I) ((com.quizlet.features.settings.viewmodels.m) this.receiver)).C(p0);
                break;
            case 4:
                com.quizlet.themes.nighttheme.a p02 = (com.quizlet.themes.nighttheme.a) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                ((I) ((com.quizlet.features.settings.viewmodels.m) this.receiver)).C(p02);
                break;
            case 5:
                String p03 = (String) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                ((C4444b) ((com.quizlet.features.settings.viewmodels.l) this.receiver)).B(p03);
                break;
            case 6:
                String token = (String) obj;
                Intrinsics.checkNotNullParameter(token, "p0");
                com.quizlet.features.settings.viewmodels.u uVar = (com.quizlet.features.settings.viewmodels.u) ((com.quizlet.features.settings.viewmodels.o) this.receiver);
                uVar.getClass();
                Intrinsics.checkNotNullParameter(token, "token");
                uVar.E();
                E.A(p0.j(uVar), null, null, new com.quizlet.features.settings.viewmodels.r(uVar, token, null), 3);
                break;
            case 7:
                String p04 = (String) obj;
                Intrinsics.checkNotNullParameter(p04, "p0");
                ((com.quizlet.features.settings.viewmodels.u) ((com.quizlet.features.settings.viewmodels.o) this.receiver)).C(p04);
                break;
            case 8:
                String token2 = (String) obj;
                Intrinsics.checkNotNullParameter(token2, "p0");
                com.quizlet.features.settings.viewmodels.u uVar2 = (com.quizlet.features.settings.viewmodels.u) ((com.quizlet.features.settings.viewmodels.o) this.receiver);
                uVar2.getClass();
                Intrinsics.checkNotNullParameter(token2, "token");
                uVar2.E();
                E.A(p0.j(uVar2), null, null, new com.quizlet.features.settings.viewmodels.r(uVar2, token2, null), 3);
                break;
            case 9:
                ServerProvidedError p05 = (ServerProvidedError) obj;
                Intrinsics.checkNotNullParameter(p05, "p0");
                C4446d c4446d = (C4446d) this.receiver;
                c4446d.getClass();
                String identifier = p05.getIdentifier();
                com.quizlet.features.settings.data.models.g gVar2 = new com.quizlet.features.settings.data.models.g(p05);
                if (Intrinsics.b(identifier, "login_incorrect_password")) {
                    gVar = null;
                } else {
                    gVar = gVar2;
                    gVar2 = null;
                }
                do {
                    s0Var = c4446d.h;
                    value = s0Var.getValue();
                } while (!s0Var.k(value, new com.quizlet.features.settings.data.states.e(gVar, null, gVar2, 2)));
            case 10:
                ServerProvidedError p06 = (ServerProvidedError) obj;
                Intrinsics.checkNotNullParameter(p06, "p0");
                com.quizlet.features.settings.viewmodels.u uVar3 = (com.quizlet.features.settings.viewmodels.u) this.receiver;
                uVar3.getClass();
                uVar3.c.h(new com.quizlet.features.settings.data.models.g(p06));
                break;
            case 11:
                ServerProvidedError p07 = (ServerProvidedError) obj;
                Intrinsics.checkNotNullParameter(p07, "p0");
                com.quizlet.features.settings.viewmodels.u uVar4 = (com.quizlet.features.settings.viewmodels.u) this.receiver;
                uVar4.getClass();
                uVar4.c.h(new com.quizlet.features.settings.data.models.g(p07));
                break;
            case 12:
                ServerProvidedError p08 = (ServerProvidedError) obj;
                Intrinsics.checkNotNullParameter(p08, "p0");
                com.quizlet.features.settings.viewmodels.u uVar5 = (com.quizlet.features.settings.viewmodels.u) this.receiver;
                uVar5.getClass();
                com.quizlet.features.settings.data.models.g gVar3 = new com.quizlet.features.settings.data.models.g(p08);
                do {
                    s0Var2 = uVar5.e;
                    value2 = s0Var2.getValue();
                } while (!s0Var2.k(value2, new com.quizlet.features.settings.data.states.t(gVar3)));
            case 13:
                com.quizlet.features.universaluploadflow.data.r p09 = (com.quizlet.features.universaluploadflow.data.r) obj;
                Intrinsics.checkNotNullParameter(p09, "p0");
                ((com.quizlet.features.universaluploadflow.viewmodel.g) ((com.quizlet.features.universaluploadflow.viewmodel.a) this.receiver)).D(p09);
                break;
            case 14:
                com.quizlet.features.universaluploadflow.flashcards.data.h p010 = (com.quizlet.features.universaluploadflow.flashcards.data.h) obj;
                Intrinsics.checkNotNullParameter(p010, "p0");
                ((com.quizlet.features.universaluploadflow.flashcards.viewmodel.e) ((com.quizlet.features.universaluploadflow.flashcards.viewmodel.a) this.receiver)).C(p010);
                break;
            case 15:
                com.quizlet.ui.models.webpage.m p011 = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(p011, "p0");
                ((com.quizlet.features.universaluploadflow.navigation.e) this.receiver).D(p011);
                break;
            case 16:
                C4459h pasteTextNavigationData = (C4459h) obj;
                Intrinsics.checkNotNullParameter(pasteTextNavigationData, "p0");
                H h = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h, "<this>");
                Intrinsics.checkNotNullParameter(pasteTextNavigationData, "pasteTextNavigationData");
                B bK = h.b.h().k("paste_text");
                if (bK != null) {
                    h.b(bK.b.c, AbstractC3206m6.a(new Pair("source", pasteTextNavigationData.b), new Pair("isPrivacySettingsPublic", Boolean.valueOf(pasteTextNavigationData.a)), new Pair("text", ""), new Pair("addMaterialFolderData", null)), J1.c(new com.quizlet.features.notes.detail.navigation.c(4, bK)));
                } else {
                    androidx.navigation.r.d(h, "paste_text");
                }
                break;
            case 17:
                C4457f flashcardsNavigationData = (C4457f) obj;
                Intrinsics.checkNotNullParameter(flashcardsNavigationData, "p0");
                H h2 = (H) this.receiver;
                Intrinsics.checkNotNullParameter(h2, "<this>");
                Intrinsics.checkNotNullParameter(flashcardsNavigationData, "flashcardsNavigationData");
                B bK2 = h2.b.h().k("flashcards");
                if (bK2 != null) {
                    h2.b(bK2.b.c, AbstractC3206m6.a(new Pair("source", flashcardsNavigationData.b), new Pair("isPrivacySettingsPublic", Boolean.valueOf(flashcardsNavigationData.a))), J1.c(new com.quizlet.features.notes.detail.navigation.c(i, bK2)));
                } else {
                    androidx.navigation.r.d(h2, "flashcards");
                }
                break;
            case 18:
                com.quizlet.features.universaluploadflow.pastetext.data.g p012 = (com.quizlet.features.universaluploadflow.pastetext.data.g) obj;
                Intrinsics.checkNotNullParameter(p012, "p0");
                ((com.quizlet.features.universaluploadflow.pastetext.viewmodel.d) ((com.quizlet.features.universaluploadflow.pastetext.viewmodel.a) this.receiver)).A(p012);
                break;
            case 19:
                com.quizlet.learn.data.onboarding.i p013 = (com.quizlet.learn.data.onboarding.i) obj;
                Intrinsics.checkNotNullParameter(p013, "p0");
                ((com.quizlet.learn.viewmodel.i) this.receiver).B(p013);
                break;
            case 20:
                com.quizlet.learn.data.onboarding.i p014 = (com.quizlet.learn.data.onboarding.i) obj;
                Intrinsics.checkNotNullParameter(p014, "p0");
                ((com.quizlet.learn.viewmodel.i) this.receiver).B(p014);
                break;
            case 21:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a p015 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                Intrinsics.checkNotNullParameter(p015, "p0");
                com.quizlet.learn.viewmodel.G g = (com.quizlet.learn.viewmodel.G) this.receiver;
                com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
                DBSession dBSessionB = fVar.x.C;
                if (dBSessionB == null || dBSessionB.getEndedTimestampMs() > 0) {
                    dBSessionB = fVar.b();
                }
                g.j1 = dBSessionB;
                com.quizlet.featuregate.features.studymodes.learn.b bVar = g.v1;
                androidx.compose.ui.text.font.o oVar = g.A1;
                if (bVar == null && g.w1 == null && g.x1 == null) {
                    E.A(p0.j(g), oVar, null, new com.quizlet.learn.viewmodel.v(g, p015, null), 2);
                } else {
                    E.A(p0.j(g), oVar, null, new com.quizlet.learn.viewmodel.s(g, p015, null), 2);
                }
                if (g.g1) {
                    com.quizlet.features.infra.basestudy.manager.f fVar2 = g.Z;
                    g.M.j(new D(g.d1, fVar2.g(), fVar2.x.c()));
                    g.g1 = false;
                }
                E.A(p0.j(g), null, null, new A(g, null), 3);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                Throwable p016 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p016, "p0");
                com.quizlet.learn.viewmodel.G.C((com.quizlet.learn.viewmodel.G) this.receiver, p016);
                break;
            case EventType.AUDIO /* 23 */:
                Throwable p017 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(p017, "p0");
                com.quizlet.learn.viewmodel.G.C((com.quizlet.learn.viewmodel.G) this.receiver, p017);
                break;
            case EventType.VIDEO /* 24 */:
                Collection ids = (Collection) obj;
                Intrinsics.checkNotNullParameter(ids, "p0");
                ((com.quizlet.local.ormlite.database.dao.e) this.receiver).getClass();
                Intrinsics.checkNotNullParameter(ids, "ids");
                break;
            case EventType.SUBS /* 25 */:
                Collection ids2 = (Collection) obj;
                Intrinsics.checkNotNullParameter(ids2, "p0");
                ((com.quizlet.local.ormlite.database.dao.e) this.receiver).getClass();
                Intrinsics.checkNotNullParameter(ids2, "ids");
                break;
            case EventType.CDN /* 26 */:
                com.quizlet.ui.models.webpage.m webPage = (com.quizlet.ui.models.webpage.m) obj;
                Intrinsics.checkNotNullParameter(webPage, "p0");
                com.quizlet.quizletandroid.ui.navigationmanagers.d dVar = (com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver;
                dVar.getClass();
                Intrinsics.checkNotNullParameter(webPage, "webPage");
                com.quizlet.quizletandroid.ui.webpages.a.a.c(dVar.a, webPage);
                break;
            case 27:
                String url = (String) obj;
                Intrinsics.checkNotNullParameter(url, "p0");
                com.quizlet.quizletandroid.ui.navigationmanagers.d dVar2 = (com.quizlet.quizletandroid.ui.navigationmanagers.d) this.receiver;
                dVar2.getClass();
                Intrinsics.checkNotNullParameter(url, "url");
                String str = DeepLinkInterstitialActivity.s;
                Context context = dVar2.a;
                context.startActivity(A4.b(context, url));
                break;
            case 28:
                String p018 = (String) obj;
                Intrinsics.checkNotNullParameter(p018, "p0");
                com.quizlet.login.common.navigation.e.d((H) this.receiver, p018);
                break;
            default:
                String p019 = (String) obj;
                Intrinsics.checkNotNullParameter(p019, "p0");
                com.quizlet.login.common.navigation.e.c((H) this.receiver, p019);
                break;
        }
        return Unit.a;
    }
}
