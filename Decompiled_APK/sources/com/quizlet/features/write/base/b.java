package com.quizlet.features.write.base;

import android.content.SharedPreferences;
import android.os.Bundle;
import com.facebook.z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3258s5;
import com.quizlet.baseui.base.f;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.interfaces.StudyableModel;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.e;
import com.quizlet.eventlogger.features.search.SearchEventLogger;
import com.quizlet.eventlogger.features.study.StudySessionQuestionEventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.generated.enums.A1;
import com.quizlet.generated.enums.G1;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.infra.legacysyncengine.net.c;
import com.quizlet.infra.legacysyncengine.net.request.g;
import com.quizlet.offline.managers.i;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import io.reactivex.rxjava3.internal.operators.observable.C;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.UUID;

/* loaded from: classes3.dex */
public abstract class b extends f {
    public EventLogger A;
    public SearchEventLogger B;
    public z C;
    public com.quizlet.offline.managers.b D;
    public com.quizlet.infra.legacysyncengine.net.f E;
    public c F;
    public d G;
    public com.quizlet.data.repository.user.a H;
    public StudySessionQuestionEventLogger I;
    public io.reactivex.rxjava3.subjects.b J;
    public Integer l;
    public Long m;
    public String n;
    public Long o;
    public G1 p;
    public String q;
    public boolean r;
    public ArrayList s;
    public StudyModeEventLogger t;
    public com.quizlet.features.infra.basestudy.data.models.dataproviders.a u;
    public com.quizlet.ads.d v;
    public io.reactivex.rxjava3.disposables.a w;
    public UserInfoCache x;
    public z y;
    public SharedPreferences z;

    @Override // com.quizlet.baseui.base.b
    public final boolean H() {
        return false;
    }

    public final DBSession O() {
        DBSession dBSession = new DBSession(this.x.getPersonId(), this.m.longValue(), this.p, A1.MOBILE_WRITE, this.r, System.currentTimeMillis());
        this.E.a(dBSession);
        return dBSession;
    }

    public abstract void P(Bundle bundle);

    public final void Q(boolean z) {
        this.r = z;
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
        if (aVar != null) {
            aVar.h.b(Boolean.valueOf(z));
        }
        if (!this.p.equals(G1.SET)) {
            throw new UnsupportedOperationException("Non-set studyable models are not implemented yet");
        }
        this.y.c(this.m.longValue(), this.p, z);
    }

    @Override // com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (bundle != null) {
            P(bundle);
        }
        Bundle extras = getIntent().getExtras();
        if (extras == null) {
            throw new RuntimeException("StudyModeActivity launched without required Bundle extras");
        }
        this.l = Integer.valueOf(extras.getInt("navigationSource"));
        this.m = Long.valueOf(extras.getLong("studyableModelId"));
        this.n = extras.getString("studyableModelTitle");
        this.o = Long.valueOf(extras.getLong("studyableModelLocalId"));
        this.p = G1.a(Integer.valueOf(extras.getInt("studyableModelType")));
        this.r = extras.getBoolean("selectedOnlyIntent");
        this.s = (ArrayList) extras.getSerializable("termsToShowIntent");
        if (this.x.b()) {
            this.v = new com.quizlet.ads.d(this.G.e.getPersonId(), this.z);
        }
        EventLogger eventLogger = this.A;
        A1 a1 = A1.MOBILE_WRITE;
        this.t = new StudyModeEventLogger(eventLogger, a1);
        if (this.q == null) {
            String string = UUID.randomUUID().toString();
            this.q = string;
            this.I.b(string);
            WriteModeActivity writeModeActivity = (WriteModeActivity) this;
            StudyModeEventLogger studyModeEventLogger = writeModeActivity.t;
            String str = writeModeActivity.q;
            G1 g1 = writeModeActivity.p;
            Integer num = writeModeActivity.l;
            com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = writeModeActivity.u;
            studyModeEventLogger.b(str, g1, num, aVar == null ? null : aVar.C, writeModeActivity.m, writeModeActivity.o, writeModeActivity.r, null, null);
        }
        this.B.n(a1, this.q);
        if (this.p == G1.SET) {
            ((i) this.D).b(this.C, Collections.singletonList(this.m));
        }
    }

    @Override // com.quizlet.baseui.base.b, androidx.fragment.app.I, android.app.Activity
    public final void onResume() {
        super.onResume();
        this.u.e();
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onSaveInstanceState(Bundle bundle) {
        super.onSaveInstanceState(bundle);
        bundle.putBoolean("selectedOnlyBundle", this.r);
        bundle.putString("studySessionId", this.q);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onStart() {
        super.onStart();
        com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = this.u;
        if (aVar != null) {
            aVar.f();
        }
        this.J = new io.reactivex.rxjava3.subjects.b();
        StudyableModelData.StudySet studySet = new StudyableModelData.StudySet(this.m.longValue());
        c cVar = this.F;
        A1 a1 = A1.MOBILE_WRITE;
        boolean z = this.r;
        this.u = AbstractC3258s5.b(this.x.getPersonId(), studySet, a1, cVar, new com.google.android.material.search.a(this, 23), this.s, z);
        WriteModeActivity writeModeActivity = (WriteModeActivity) this;
        com.quizlet.quizletandroid.ui.studymodes.write.a aVar2 = new com.quizlet.quizletandroid.ui.studymodes.write.a(writeModeActivity, 0);
        io.reactivex.rxjava3.subjects.b bVar = writeModeActivity.J;
        com.quizlet.billing.subscriptions.c cVar2 = new com.quizlet.billing.subscriptions.c(2);
        io.reactivex.rxjava3.internal.functions.b bVar2 = io.reactivex.rxjava3.internal.functions.d.c;
        writeModeActivity.w.b(bVar.u(aVar2, cVar2, bVar2));
        io.reactivex.rxjava3.subjects.f fVar = this.u.g;
        final int i = 0;
        io.reactivex.rxjava3.functions.d dVar = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.features.write.base.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i) {
                    case 0:
                        this.b.w.b((io.reactivex.rxjava3.disposables.b) obj);
                        break;
                    default:
                        StudyableModel studyableModel = (StudyableModel) obj;
                        this.b.H.s("WriteModeActivity", studyableModel.getTitle() == null ? "" : studyableModel.getTitle(), studyableModel.getStudyableId().longValue(), studyableModel.getStudyableType(), A1.MOBILE_WRITE);
                        break;
                }
            }
        };
        g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        fVar.getClass();
        y(new io.reactivex.rxjava3.internal.operators.completable.i(fVar, dVar, gVar, bVar2, bVar2).f(new e(this, 11), io.reactivex.rxjava3.internal.functions.d.e));
        J j = this.u.l;
        final int i2 = 0;
        io.reactivex.rxjava3.functions.d dVar2 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.features.write.base.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i2) {
                    case 0:
                        this.b.w.b((io.reactivex.rxjava3.disposables.b) obj);
                        break;
                    default:
                        StudyableModel studyableModel = (StudyableModel) obj;
                        this.b.H.s("WriteModeActivity", studyableModel.getTitle() == null ? "" : studyableModel.getTitle(), studyableModel.getStudyableId().longValue(), studyableModel.getStudyableType(), A1.MOBILE_WRITE);
                        break;
                }
            }
        };
        j.getClass();
        final int i3 = 1;
        y(new C4887f(new C(j, dVar2, bVar2), 5).u(new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.features.write.base.a
            public final /* synthetic */ b b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                switch (i3) {
                    case 0:
                        this.b.w.b((io.reactivex.rxjava3.disposables.b) obj);
                        break;
                    default:
                        StudyableModel studyableModel = (StudyableModel) obj;
                        this.b.H.s("WriteModeActivity", studyableModel.getTitle() == null ? "" : studyableModel.getTitle(), studyableModel.getStudyableId().longValue(), studyableModel.getStudyableType(), A1.MOBILE_WRITE);
                        break;
                }
            }
        }, new com.quizlet.billing.subscriptions.c(2), bVar2));
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public void onStop() {
        super.onStop();
        if (this.u != null) {
            this.w.d();
            this.u.f();
            this.u = null;
        }
    }
}
