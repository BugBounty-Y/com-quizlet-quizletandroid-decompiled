package com.quizlet.features.flashcards;

import androidx.lifecycle.p0;
import assistantMode.enums.EnumC1448b;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.model.ScanNotesPaywallEventLog;
import com.quizlet.features.infra.folder.create.CreateFolderModalFragment;
import com.quizlet.features.infra.models.flashcards.FlashcardSettings$FlashcardSettingsState;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.y0;

/* renamed from: com.quizlet.features.flashcards.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C4242p extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C4242p(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                S s = (S) this.receiver;
                s.getClass();
                s.L(EnumC1448b.d);
                break;
            case 1:
                S s2 = (S) this.receiver;
                s2.getClass();
                s2.L(EnumC1448b.c);
                break;
            case 2:
                ((S) this.receiver).O();
                break;
            case 3:
                ((S) this.receiver).I();
                break;
            case 4:
                S s3 = (S) this.receiver;
                com.quizlet.features.flashcards.engine.h hVar = s3.c;
                if (hVar.d().e) {
                    s3.I();
                }
                com.quizlet.features.infra.basestudy.manager.f.k(s3.w, "settings", null, 6);
                s3.y = true;
                d0 d0Var = s3.r;
                FlashcardSettings$FlashcardSettingsState flashcardSettings$FlashcardSettingsState = new FlashcardSettings$FlashcardSettingsState(hVar.d().a.a, hVar.d().b.a, hVar.d().c, hVar.d().d, hVar.d().e, hVar.d().f, hVar.d().g, hVar.d().h, hVar.d().b().a);
                com.quizlet.features.infra.basestudy.manager.f fVar = hVar.n;
                List list = fVar.x.u;
                Intrinsics.checkNotNullExpressionValue(list, "getSelectedTerms(...)");
                int size = list.size();
                ArrayList arrayList = fVar.x.z;
                Intrinsics.checkNotNullExpressionValue(arrayList, "getAvailableStudiableCardSideLabels(...)");
                d0Var.h(new com.quizlet.features.flashcards.data.h(flashcardSettings$FlashcardSettingsState, hVar.o, hVar.p, size, arrayList));
                break;
            case 5:
                ((S) this.receiver).J();
                break;
            case 6:
                S s4 = (S) this.receiver;
                com.quizlet.features.flashcards.data.b bVar = s4.G().j;
                if (bVar != null) {
                    boolean z = bVar.f;
                    boolean z2 = !z;
                    s4.t.l(com.quizlet.features.flashcards.data.o.a(s4.G(), 0, 0, 0, 0, false, false, false, false, null, com.quizlet.features.flashcards.data.b.b(bVar, z2, null, 111), 511));
                    com.quizlet.features.flashcards.engine.h hVar2 = s4.c;
                    com.quizlet.features.flashcards.data.e eVar = hVar2.i;
                    AbstractC3146g0 abstractC3146g0 = eVar != null ? eVar.a : null;
                    com.quizlet.features.flashcards.data.b bVar2 = abstractC3146g0 instanceof com.quizlet.features.flashcards.data.b ? (com.quizlet.features.flashcards.data.b) abstractC3146g0 : null;
                    Long lValueOf = bVar2 != null ? Long.valueOf(bVar2.b) : null;
                    if (lValueOf != null) {
                        long jLongValue = lValueOf.longValue();
                        com.quizlet.features.infra.basestudy.manager.f fVar2 = hVar2.n;
                        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = fVar2.x;
                        if (aVar.d()) {
                            DBTerm dBTerm = (DBTerm) CollectionsKt.N(aVar.t, new com.quizlet.eventlogger.features.folder.a(2, lValueOf));
                            DBSelectedTerm dBSelectedTerm = (DBSelectedTerm) aVar.B.c(jLongValue);
                            if (dBTerm == null) {
                                timber.log.c.a.o("Tried to change selected state to '%s' on nonexistent term: %d", Boolean.valueOf(z2), lValueOf);
                            } else {
                                com.quizlet.infra.legacysyncengine.net.f fVar3 = fVar2.g;
                                if (!z && (dBSelectedTerm == null || dBSelectedTerm.getDeleted())) {
                                    long personId = fVar2.a.getPersonId();
                                    long setId = dBTerm.getSetId();
                                    Instant instantNow = Instant.now();
                                    Intrinsics.checkNotNullExpressionValue(instantNow, "now(...)");
                                    fVar3.a(new DBSelectedTerm(personId, setId, jLongValue, instantNow.getEpochSecond(), 7));
                                } else if (!z || dBSelectedTerm == null || dBSelectedTerm.getDeleted()) {
                                    timber.log.c.a.g("No change needed to unselect term id: %d", lValueOf);
                                } else {
                                    dBSelectedTerm.setDeleted(true);
                                    fVar3.a(dBSelectedTerm);
                                }
                            }
                        } else {
                            timber.log.c.a.o("Tried to change term selected state before study mode data provider loaded", new Object[0]);
                        }
                        com.quizlet.features.flashcards.logging.a.a(hVar2.d, "star_button_tapped", null, null, Boolean.valueOf(z2), 54);
                    }
                }
                break;
            case 7:
                ((S) this.receiver).J();
                break;
            case 8:
                ((S) this.receiver).O();
                break;
            case 9:
                S s5 = (S) this.receiver;
                s5.getClass();
                kotlinx.coroutines.E.A(p0.j(s5), null, null, new C(s5, null), 3);
                break;
            case 10:
                S s6 = (S) this.receiver;
                y0 y0Var = s6.C;
                if (y0Var == null || !y0Var.a()) {
                    s6.C = kotlinx.coroutines.E.A(p0.j(s6), com.facebook.appevents.iap.u.d(), null, new B(s6, null), 2);
                }
                break;
            case 11:
                S s7 = (S) this.receiver;
                s7.getClass();
                kotlinx.coroutines.E.A(p0.j(s7), null, null, new F(s7, null), 3);
                break;
            case 12:
                S s8 = (S) this.receiver;
                s8.getClass();
                kotlinx.coroutines.E.A(p0.j(s8), null, null, new I(s8, null), 3);
                break;
            case 13:
                S s9 = (S) this.receiver;
                s9.getClass();
                kotlinx.coroutines.E.A(p0.j(s9), null, null, new H(s9, null), 3);
                break;
            case 14:
                ((S) this.receiver).M();
                break;
            case 15:
                com.quizlet.features.flashcards.settings.j jVar = (com.quizlet.features.flashcards.settings.j) ((com.quizlet.features.flashcards.settings.l) this.receiver);
                com.quizlet.features.flashcards.logging.d dVar = jVar.c;
                dVar.getClass();
                com.quizlet.features.flashcards.logging.d.a(dVar, "options_restart_button_tapped", null, null, null, 62);
                kotlinx.coroutines.E.A(p0.j(jVar), null, null, new com.quizlet.features.flashcards.settings.h(jVar, null), 3);
                break;
            case 16:
                ((com.quizlet.assembly.compose.modals.x) this.receiver).a();
                break;
            case 17:
                ((com.quizlet.assembly.compose.modals.x) this.receiver).a();
                break;
            case 18:
                Y y = (Y) ((com.quizlet.features.home.viewmodel.e) this.receiver);
                y.A.a("clicked_search", "LoggedInHomepage", "logged_in_home");
                y.v.a("clicked_search", null);
                y.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.e.a);
                break;
            case 19:
                Y y2 = (Y) ((com.quizlet.features.home.viewmodel.e) this.receiver);
                y2.A.a("clicked_profile", "LoggedInHomepage", "logged_in_home");
                y2.r1.j(com.quizlet.quizletandroid.ui.startpage.nav2.screenstates.d.a);
                break;
            case 20:
                ((CreateFolderModalFragment) this.receiver).H(false, false);
                break;
            case 21:
                ((CreateFolderModalFragment) this.receiver).H(false, false);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ((CreateFolderModalFragment) this.receiver).H(false, false);
                break;
            case EventType.AUDIO /* 23 */:
                ((CreateFolderModalFragment) this.receiver).H(false, false);
                break;
            case EventType.VIDEO /* 24 */:
                ((com.quizlet.assembly.compose.modals.x) this.receiver).a();
                break;
            case EventType.SUBS /* 25 */:
                ((com.quizlet.assembly.compose.modals.x) this.receiver).a();
                break;
            case EventType.CDN /* 26 */:
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.receiver).n();
                break;
            case 27:
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.receiver).p();
                break;
            case 28:
                ((com.quizlet.features.infra.folder.menu.viewmodel.n) this.receiver).p();
                break;
            default:
                com.quizlet.features.notes.paywall.l lVar = (com.quizlet.features.notes.paywall.l) ((com.quizlet.features.notes.paywall.i) this.receiver);
                com.google.mlkit.vision.documentscanner.internal.c cVar = lVar.b;
                cVar.getClass();
                ((EventLogger) cVar.b).l(new ScanNotesPaywallEventLog("notes_meter_exceeded", "notes_to_value_paywall_ugprade_clicked"));
                lVar.d.j(com.quizlet.features.notes.paywall.e.a);
                break;
        }
        return Unit.a;
    }
}
