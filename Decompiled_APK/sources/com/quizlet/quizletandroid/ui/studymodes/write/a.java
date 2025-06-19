package com.quizlet.quizletandroid.ui.studymodes.write;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3537t4;
import com.quizlet.db.data.models.persisted.DBSession;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBAnswerFields;
import com.quizlet.generated.enums.O1;
import com.quizlet.quizletandroid.databinding.C4608l;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ WriteModeActivity b;

    public /* synthetic */ a(WriteModeActivity writeModeActivity, int i) {
        this.a = i;
        this.b = writeModeActivity;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = (com.quizlet.features.infra.basestudy.data.models.dataproviders.a) obj;
                final WriteModeActivity writeModeActivity = this.b;
                writeModeActivity.c1 = new HashMap();
                writeModeActivity.Z = new HashMap();
                writeModeActivity.M = new ArrayList();
                writeModeActivity.V = new ArrayList();
                writeModeActivity.W = new ArrayList();
                writeModeActivity.X = new ArrayList();
                Iterator it2 = aVar.s.iterator();
                while (true) {
                    boolean z = false;
                    if (!it2.hasNext()) {
                        WriteStudyModeConfig writeStudyModeConfigF = writeModeActivity.t1.f();
                        if ("photo".equals(writeModeActivity.u.f.getDefLang()) && O1.WORD.equals(writeStudyModeConfigF.a)) {
                            boolean z2 = true;
                            if (writeStudyModeConfigF.b) {
                                writeStudyModeConfigF.b = false;
                                z = true;
                            }
                            if (writeStudyModeConfigF.d) {
                                z2 = z;
                            } else {
                                writeStudyModeConfigF.d = true;
                            }
                            if (z2) {
                                writeModeActivity.t1.i(writeStudyModeConfigF);
                            }
                        }
                        final DBSession dBSession = aVar.C;
                        if (dBSession != null) {
                            long id = dBSession.getId();
                            com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.ANSWER);
                            bVar.b(Long.valueOf(id), DBAnswerFields.SESSION);
                            bVar.b(Long.valueOf(writeModeActivity.x.getPersonId()), DBAnswerFields.PERSON);
                            final com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                            final ArrayList arrayList = new ArrayList();
                            final com.quizlet.infra.legacysyncengine.datasources.f fVar = new com.quizlet.infra.legacysyncengine.datasources.f(arrayList, 9);
                            writeModeActivity.k1.e(aVarA, fVar);
                            writeModeActivity.K.b(writeModeActivity.k1.c(aVarA, AbstractC3537t4.g(com.quizlet.infra.legacysyncengine.net.b.a)).i(new io.reactivex.rxjava3.functions.a() { // from class: com.quizlet.quizletandroid.ui.studymodes.write.c
                                @Override // io.reactivex.rxjava3.functions.a
                                public final void run() {
                                    WriteModeActivity writeModeActivity2 = writeModeActivity;
                                    writeModeActivity2.k1.a(aVarA, fVar);
                                    if (writeModeActivity2.u != null) {
                                        writeModeActivity2.b0(dBSession, arrayList);
                                    }
                                }
                            }).t());
                        } else {
                            writeModeActivity.b0(null, new ArrayList());
                        }
                        writeModeActivity.w.b(aVar.i.s(writeModeActivity.s1.i()).u(new a(writeModeActivity, 1), io.reactivex.rxjava3.internal.functions.d.e, io.reactivex.rxjava3.internal.functions.d.c));
                        break;
                    } else {
                        DBTerm dBTerm = (DBTerm) it2.next();
                        writeModeActivity.c1.put(Long.valueOf(dBTerm.getId()), dBTerm);
                        writeModeActivity.Z.put(Long.valueOf(dBTerm.getId()), 0);
                    }
                }
                break;
            default:
                WriteModeActivity writeModeActivity2 = this.b;
                WriteModeResultsView writeModeResultsView = ((C4608l) writeModeActivity2.k).e;
                writeModeResultsView.p.notifyDataSetChanged();
                writeModeResultsView.h.q();
                ((C4608l) writeModeActivity2.k).c.m.notifyDataSetChanged();
                break;
        }
    }
}
