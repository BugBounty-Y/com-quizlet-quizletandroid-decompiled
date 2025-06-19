package com.quizlet.features.setpage.header.ui;

import androidx.lifecycle.p0;
import com.comscore.streaming.EventType;
import com.quizlet.assembly.compose.modals.x;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.setpage.viewmodel.C;
import com.quizlet.features.setpage.viewmodel.C4428b;
import com.quizlet.features.setpage.viewmodel.D;
import com.quizlet.features.setpage.viewmodel.E;
import com.quizlet.features.setpage.viewmodel.F;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.features.settings.SettingsActivity;
import com.quizlet.features.settings.viewmodels.I;
import com.quizlet.features.settings.viewmodels.j;
import com.quizlet.features.settings.viewmodels.k;
import com.quizlet.features.settings.viewmodels.n;
import com.quizlet.features.settings.viewmodels.p;
import com.quizlet.features.userprofile.data.o;
import com.quizlet.features.userprofile.data.q;
import com.quizlet.features.userprofile.data.r;
import com.quizlet.features.userprofile.data.v;
import com.quizlet.features.userprofile.data.w;
import com.quizlet.ui.models.webpage.i;
import com.quizlet.ui.models.webpage.l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;

/* loaded from: classes3.dex */
public final /* synthetic */ class a extends C4956o implements Function0 {
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, Object obj, Class cls, String str, String str2, int i2, int i3) {
        super(i, i2, cls, obj, str, str2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                P p = (P) this.receiver;
                p.f.A("set_page_match_study_mode_clicked");
                p.H(new E(p, null));
                break;
            case 1:
                P p2 = (P) this.receiver;
                p2.f.A("set_page_blast_study_mode_clicked");
                p2.M(p2.F());
                break;
            case 2:
                P p3 = (P) this.receiver;
                p3.f.A("set_page_blocks_study_mode_clicked");
                p3.N(p3.F());
                break;
            case 3:
                P p4 = (P) this.receiver;
                p4.f.A("set_page_flashcards_study_mode_clicked");
                p4.H(new C(p4, null));
                break;
            case 4:
                P p5 = (P) this.receiver;
                p5.f.A("set_page_learn_study_mode_clicked");
                p5.I(new C4428b(p5, 0), new D(p5, null, null));
                break;
            case 5:
                P p6 = (P) this.receiver;
                p6.f.A("set_page_test_study_mode_clicked");
                p6.I(new C4428b(p6, 3), new F(p6, null));
                break;
            case 6:
                P p7 = (P) this.receiver;
                p7.f.A("set_page_match_study_mode_clicked");
                p7.H(new E(p7, null));
                break;
            case 7:
                P p8 = (P) this.receiver;
                p8.f.A("set_page_blast_study_mode_clicked");
                p8.M(p8.F());
                break;
            case 8:
                P p9 = (P) this.receiver;
                p9.f.A("set_page_blocks_study_mode_clicked");
                p9.N(p9.F());
                break;
            case 9:
                ((SettingsActivity) this.receiver).finish();
                break;
            case 10:
                ((com.quizlet.infra.contracts.debug.a) this.receiver).q();
                break;
            case 11:
                ((I) ((p) this.receiver)).p.h(com.quizlet.features.settings.data.events.f.a);
                break;
            case 12:
                ((I) ((p) this.receiver)).p.h(new com.quizlet.features.settings.data.events.e(i.c));
                break;
            case 13:
                ((I) ((p) this.receiver)).p.h(new com.quizlet.features.settings.data.events.e(l.c));
                break;
            case 14:
                ((I) ((p) this.receiver)).p.h(com.quizlet.features.settings.data.events.b.a);
                break;
            case 15:
                ((I) ((p) this.receiver)).p.h(new com.quizlet.features.settings.data.events.e(com.quizlet.ui.models.webpage.c.c));
                break;
            case 16:
                ((I) ((p) this.receiver)).i.a(false);
                break;
            case 17:
                ((I) ((p) this.receiver)).p.h(com.quizlet.features.settings.data.events.a.a);
                break;
            case 18:
                ((I) ((p) this.receiver)).g.getClass();
                break;
            case 19:
                ((I) ((p) this.receiver)).p.h(com.quizlet.features.settings.data.events.c.a);
                break;
            case 20:
                ((I) ((p) this.receiver)).p.h(new com.quizlet.features.settings.data.events.e(com.quizlet.ui.models.webpage.e.c));
                break;
            case 21:
                I i = (I) ((p) this.receiver);
                i.h.a.I("toggle_autodownload_setting_upsell");
                i.p.h(com.quizlet.features.settings.data.events.d.a);
                break;
            case EventType.WINDOW_STATE /* 22 */:
                k kVar = (k) ((n) this.receiver);
                kVar.getClass();
                kotlinx.coroutines.E.A(p0.j(kVar), kVar.e, null, new j(kVar, null), 2);
                break;
            case EventType.AUDIO /* 23 */:
                ((x) this.receiver).a();
                break;
            case EventType.VIDEO /* 24 */:
                com.quizlet.features.userprofile.data.x xVar = (com.quizlet.features.userprofile.data.x) this.receiver;
                xVar.getClass();
                kotlinx.coroutines.E.A(p0.j(xVar), null, null, new v(xVar, null), 3);
                break;
            case EventType.SUBS /* 25 */:
                com.quizlet.features.userprofile.data.x xVar2 = (com.quizlet.features.userprofile.data.x) this.receiver;
                DBUser dBUser = xVar2.d.r;
                if (dBUser != null) {
                    kotlinx.coroutines.E.A(p0.j(xVar2), null, null, new r(xVar2, dBUser.getProfileImageId(), !dBUser.getIsUnderAge(), null), 3);
                }
                break;
            case EventType.CDN /* 26 */:
                com.quizlet.features.userprofile.data.x xVar3 = (com.quizlet.features.userprofile.data.x) this.receiver;
                com.quizlet.features.userprofile.a aVar = xVar3.f;
                aVar.getClass();
                aVar.a.l(com.quizlet.features.userprofile.a.a("clicked_settings"));
                kotlinx.coroutines.E.A(p0.j(xVar3), null, null, new w(xVar3, null), 3);
                break;
            case 27:
                com.quizlet.features.userprofile.data.x xVar4 = (com.quizlet.features.userprofile.data.x) this.receiver;
                com.quizlet.features.userprofile.a aVar2 = xVar4.f;
                aVar2.getClass();
                aVar2.a.l(com.quizlet.features.userprofile.a.a("view_all_achievements"));
                kotlinx.coroutines.E.A(p0.j(xVar4), null, null, new o(xVar4, null), 3);
                break;
            case 28:
                com.quizlet.features.userprofile.data.x xVar5 = (com.quizlet.features.userprofile.data.x) this.receiver;
                com.quizlet.features.userprofile.a aVar3 = xVar5.f;
                aVar3.getClass();
                aVar3.a.l(com.quizlet.features.userprofile.a.a("clicked_activity_center"));
                kotlinx.coroutines.E.A(p0.j(xVar5), null, null, new com.quizlet.features.userprofile.data.p(xVar5, null), 3);
                break;
            default:
                com.quizlet.features.userprofile.data.x xVar6 = (com.quizlet.features.userprofile.data.x) this.receiver;
                com.quizlet.features.userprofile.a aVar4 = xVar6.f;
                aVar4.getClass();
                aVar4.a.l(com.quizlet.features.userprofile.a.a("clicked_back_button"));
                kotlinx.coroutines.E.A(p0.j(xVar6), null, null, new q(xVar6, null), 3);
                break;
        }
        return Unit.a;
    }
}
