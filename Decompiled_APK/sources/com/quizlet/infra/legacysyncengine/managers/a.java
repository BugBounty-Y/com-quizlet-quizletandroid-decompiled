package com.quizlet.infra.legacysyncengine.managers;

import android.content.Context;
import android.content.Intent;
import com.google.firebase.perf.metrics.Trace;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.generated.enums.O1;
import com.quizlet.offline.managers.j;
import com.quizlet.quizletandroid.ui.profile.UserSetListFragment;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) throws Exception {
        Intent intent;
        int i = 0;
        Object obj2 = this.c;
        Object obj3 = this.b;
        switch (this.a) {
            case 0:
                ((d) obj3).d((DBUser) obj);
                ((Trace) obj2).stop();
                return;
            case 1:
                j launchBehavior = (j) obj;
                UserSetListFragment userSetListFragment = (UserSetListFragment) obj3;
                Context context = userSetListFragment.getContext();
                if (context == null) {
                    return;
                }
                DBStudySet dBStudySet = (DBStudySet) obj2;
                if (launchBehavior == j.a) {
                    long setId = dBStudySet.getSetId();
                    com.quizlet.features.setpage.e eVar = SetPageActivity.h1;
                    Intrinsics.checkNotNullParameter(context, "context");
                    userSetListFragment.startActivityForResult(com.quizlet.features.setpage.e.b(eVar, context, setId, null, null, null, null, false, null, 252), 201);
                    return;
                }
                com.quizlet.offline.managers.i iVar = (com.quizlet.offline.managers.i) userSetListFragment.y;
                iVar.getClass();
                Intrinsics.checkNotNullParameter(launchBehavior, "launchBehavior");
                if (launchBehavior == j.b) {
                    iVar.a.I("warned_missing_offline_content");
                }
                com.quizlet.offline.managers.b bVar = userSetListFragment.y;
                Context contextRequireContext = userSetListFragment.requireContext();
                Context context2 = userSetListFragment.requireContext();
                long setId2 = dBStudySet.getSetId();
                com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                Intrinsics.checkNotNullParameter(context2, "context");
                ((com.quizlet.offline.managers.i) bVar).d(contextRequireContext, launchBehavior, com.quizlet.features.setpage.e.b(eVar2, context2, setId2, null, null, null, null, false, null, 252), new com.quizlet.infra.legacysyncengine.tasks.parse.b(userSetListFragment, 11));
                return;
            case 2:
                DBStudySet dBStudySet2 = (DBStudySet) obj;
                com.quizlet.quizletandroid.ui.setcreation.activities.d dVar = (com.quizlet.quizletandroid.ui.setcreation.activities.d) obj3;
                dVar.getClass();
                O1 o1 = O1.WORD;
                O1 o12 = (O1) obj2;
                if (o12 == o1) {
                    dVar.startActivityForResult(EditSetLanguageSelectionActivity.Q(dVar, dBStudySet2.getLanguageCode(o1), true), 3000);
                    return;
                }
                O1 o13 = O1.DEFINITION;
                if (o12 == o13) {
                    dVar.startActivityForResult(EditSetLanguageSelectionActivity.Q(dVar, dBStudySet2.getLanguageCode(o13), false), 4000);
                    return;
                }
                return;
            case 3:
                EditSetFragment editSetFragment = ((com.quizlet.quizletandroid.ui.setcreation.activities.d) obj3).B;
                if (editSetFragment == null || (intent = (Intent) obj2) == null) {
                    return;
                }
                long longExtra = intent.getLongExtra("termId", 0L);
                com.quizlet.data.repository.explanations.question.a aVar = editSetFragment.s;
                if (aVar == null) {
                    Intrinsics.m("imageUploadFeatureWrapper");
                    throw null;
                }
                io.reactivex.rxjava3.internal.observers.e eVarI = ((assistantMode.utils.studiableMetadata.b) aVar.a).L((androidx.work.impl.model.c) aVar.c).i(new com.quizlet.quizletandroid.ui.setcreation.fragments.g(editSetFragment, longExtra, i), com.quizlet.quizletandroid.ui.setcreation.fragments.e.c);
                Intrinsics.checkNotNullExpressionValue(eVarI, "subscribe(...)");
                editSetFragment.I(eVarI);
                return;
            default:
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = (com.quizlet.quizletandroid.ui.setcreation.managers.i) obj3;
                iVar2.getClass();
                timber.log.c.a.g("This study set looks to be new and untouched so it will be discarded", new Object[0]);
                ((DBStudySet) obj).setDeleted(true);
                DBModel[] dBModelArr = {iVar2.m};
                i iVar3 = iVar2.d;
                iVar3.c(dBModelArr);
                List list = (List) obj2;
                if (list != null) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        ((DBTerm) it2.next()).setDeleted(true);
                    }
                    iVar3.a(list, null);
                    return;
                }
                return;
        }
    }
}
