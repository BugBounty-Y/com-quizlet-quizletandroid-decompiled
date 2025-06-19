package com.quizlet.eventlogger;

import com.braze.events.ContentCardsUpdatedEvent;
import com.comscore.streaming.EventType;
import com.quizlet.db.data.orm.query.IdMappedQuery;
import com.quizlet.features.setpage.screenstates.m;
import com.quizlet.features.setpage.viewmodel.P;
import com.quizlet.infra.legacysyncengine.datasources.o;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.C4756b;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import com.quizlet.quizletandroid.ui.usersettings.fragments.CropImageFragment;
import com.quizlet.uicommon.ui.common.dialogs.k;
import io.reactivex.rxjava3.internal.observers.h;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import io.reactivex.rxjava3.subjects.p;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements io.reactivex.rxjava3.functions.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ e(EventLogUploader eventLogUploader, com.quizlet.background.eventlogging.a aVar) {
        this.a = 0;
        this.b = eventLogUploader;
    }

    @Override // io.reactivex.rxjava3.functions.a
    public final void run() {
        switch (this.a) {
            case 0:
                EventLogUploader eventLogUploader = (EventLogUploader) this.b;
                eventLogUploader.getClass();
                timber.log.c.a.m("Event log upload completed", new Object[0]);
                eventLogUploader.i(false);
                return;
            case 1:
                EventFileWriter eventFileWriter = (EventFileWriter) this.b;
                synchronized (eventFileWriter) {
                    eventFileWriter.a = 0;
                }
                return;
            case 2:
                ((com.quizlet.explanations.questiondetail.viewmodel.f) this.b).o.j(Boolean.FALSE);
                return;
            case 3:
                ((com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) this.b).h.l(Boolean.FALSE);
                return;
            case 4:
                com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) this.b;
                o oVar = (o) aVar.c;
                if (oVar == null) {
                    Intrinsics.m("answersDataSource");
                    throw null;
                }
                oVar.g();
                o oVar2 = (o) aVar.d;
                if (oVar2 != null) {
                    oVar2.g();
                    return;
                } else {
                    Intrinsics.m("questionAttributeDataSource");
                    throw null;
                }
            case 5:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar2 = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) this.b;
                timber.log.c.a.d("Data sources have finished loading but no studyable model could be found %d/%s", Long.valueOf(aVar2.b), aVar2.a);
                return;
            case 6:
                com.quizlet.features.infra.basestudy.manager.f fVar = (com.quizlet.features.infra.basestudy.manager.f) this.b;
                fVar.w.b(fVar.x);
                fVar.w.onComplete();
                return;
            case 7:
                ((com.quizlet.features.infra.studysetting.datasource.a) this.b).g();
                return;
            case 8:
                com.quizlet.features.setpage.progress.presentation.viewmodel.a aVar3 = (com.quizlet.features.setpage.progress.presentation.viewmodel.a) this.b;
                aVar3.g.c();
                com.quizlet.data.repository.user.e eVar = aVar3.j;
                ((com.quizlet.features.infra.studysetting.datasource.a) eVar.b).d();
                ((com.quizlet.features.infra.studysetting.datasource.a) eVar.c).d();
                ((io.reactivex.rxjava3.subjects.d) ((com.quizlet.data.repository.explanations.exercise.b) eVar.d).c).b(Unit.a);
                return;
            case 9:
                ((com.quizlet.baseui.base.b) this.b).I(false);
                return;
            case 10:
                ((P) this.b).e1.j(m.a);
                return;
            case 11:
                com.quizlet.features.write.base.b bVar = (com.quizlet.features.write.base.b) this.b;
                bVar.J.b(bVar.u);
                bVar.J.onComplete();
                return;
            case 12:
                ((com.quizlet.infra.legacysyncengine.managers.d) this.b).f();
                return;
            case 13:
                ((C4899s) this.b).onComplete();
                return;
            case 14:
                com.quizlet.data.repository.classfolder.e eVar2 = (com.quizlet.data.repository.classfolder.e) this.b;
                com.quizlet.infra.legacysyncengine.net.listeners.d dVar = (com.quizlet.infra.legacysyncengine.net.listeners.d) eVar2.c;
                dVar.a.b.computeIfPresent(dVar.b.convertStaleLocalIds((IdMappedQuery) eVar2.b), new com.quizlet.infra.legacysyncengine.b(2));
                return;
            case 15:
                ((p) this.b).onComplete();
                return;
            case 16:
                ((com.quizlet.login.oldlogin.o) this.b).s.j(Boolean.FALSE);
                return;
            case 17:
                com.quizlet.quizletandroid.braze.data.a aVar4 = (com.quizlet.quizletandroid.braze.data.a) this.b;
                aVar4.a.removeSingleSubscription(aVar4, ContentCardsUpdatedEvent.class);
                return;
            case 18:
                ((com.bumptech.glide.load.data.d) this.b).i(null);
                return;
            case 19:
                String str = GroupFragment.M;
                ((k) ((GroupFragment) this.b).E.getValue()).dismiss();
                return;
            case 20:
                ((C4756b) this.b).h.setSelected(false);
                return;
            case 21:
                WriteModeActivity writeModeActivity = (WriteModeActivity) this.b;
                writeModeActivity.Y(writeModeActivity.u.C);
                return;
            case EventType.WINDOW_STATE /* 22 */:
                String str2 = ChangeProfileImageFragment.w;
                ((ChangeProfileImageFragment) this.b).a0(false);
                return;
            default:
                CropImageFragment cropImageFragment = (CropImageFragment) this.b;
                h hVar = cropImageFragment.r;
                if (hVar == null || hVar.c()) {
                    return;
                }
                cropImageFragment.Q(false);
                return;
        }
    }

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
