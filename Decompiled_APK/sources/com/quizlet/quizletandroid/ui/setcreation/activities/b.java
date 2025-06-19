package com.quizlet.quizletandroid.ui.setcreation.activities;

import android.content.Intent;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3107b6;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4600d;
import com.quizlet.quizletandroid.sessionhelpers.EditSessionLoggingHelperState;
import com.quizlet.quizletandroid.sessionhelpers.SavedAction;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ d b;

    public /* synthetic */ b(d dVar, int i) {
        this.a = i;
        this.b = dVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        int size;
        ArrayList arrayList;
        List listUnmodifiableList = null;
        int i = 2;
        int i2 = 1;
        d dVar = this.b;
        switch (this.a) {
            case 0:
                if (!((com.quizlet.offline.managers.i) dVar.z).i) {
                    dVar.l.j(Boolean.TRUE);
                    break;
                } else {
                    dVar.D.setEnabled(false);
                    dVar.C.setVisibility(0);
                    com.quizlet.quizletandroid.ui.setcreation.managers.i iVar = dVar.y;
                    com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = dVar.B.A;
                    if (fVar != null && (arrayList = fVar.p) != null) {
                        listUnmodifiableList = Collections.unmodifiableList(arrayList);
                    }
                    com.quizlet.infra.legacysyncengine.net.f fVar2 = dVar.r;
                    if (listUnmodifiableList == null) {
                        size = 0;
                    } else {
                        iVar.getClass();
                        size = listUnmodifiableList.size();
                    }
                    if (iVar.m == null) {
                        timber.log.c.a(new RuntimeException("Tried to validateSet before mStudySet initialized"));
                    } else if (listUnmodifiableList == null) {
                        timber.log.c.a(new RuntimeException("Tried to validateSet with invalid parameters: terms == null"));
                    } else {
                        Iterator it2 = listUnmodifiableList.iterator();
                        int i3 = 0;
                        while (true) {
                            if (it2.hasNext()) {
                                if (((DBTerm) it2.next()).hasValidUserContent()) {
                                    i3++;
                                }
                                if (i3 >= 2) {
                                    if (!iVar.m.getIsCreated()) {
                                        if (org.apache.commons.lang3.e.c(iVar.m.getTitle())) {
                                            iVar.a(R.string.title_cannot_be_empty_message, false);
                                            timber.log.c.a.d("Title cannot be empty", new Object[0]);
                                        } else if (org.apache.commons.lang3.e.c(iVar.m.getWordLang()) && org.apache.commons.lang3.e.c(iVar.m.getDefLang())) {
                                            iVar.a(R.string.term_languages_cannot_be_empty_message, true);
                                        } else if (org.apache.commons.lang3.e.c(iVar.m.getWordLang())) {
                                            iVar.a(R.string.word_language_cannot_be_empty_message, true);
                                        } else if (org.apache.commons.lang3.e.c(iVar.m.getDefLang())) {
                                            iVar.a(R.string.definition_language_cannot_be_empty_message, true);
                                        }
                                    }
                                    J jQ = iVar.o.m().q(new com.quizlet.infra.legacysyncengine.tasks.parse.b(iVar, 19));
                                    Objects.requireNonNull(fVar2);
                                    jQ.m(new com.quizlet.infra.legacysyncengine.net.d(fVar2, 2), SubsamplingScaleImageView.TILE_SIZE_AUTO).m(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i2), SubsamplingScaleImageView.TILE_SIZE_AUTO).m(new com.quizlet.infra.legacysyncengine.net.d(fVar2, 0), SubsamplingScaleImageView.TILE_SIZE_AUTO).l(new com.quizlet.quizletandroid.ui.setcreation.imageupload.a(i)).x(16).i(new com.quizlet.quizletandroid.ui.setcreation.managers.e(iVar, size, 1), new com.quizlet.quizletandroid.ui.setcreation.managers.e(iVar, size, 2));
                                    break;
                                }
                            } else {
                                iVar.a(R.string.must_have_two_terms_message, false);
                                timber.log.c.a.d("Too few terms", new Object[0]);
                            }
                        }
                    }
                    com.quizlet.quizletandroid.ui.setcreation.managers.g gVar = (com.quizlet.quizletandroid.ui.setcreation.managers.g) iVar.p.get();
                    if (gVar != null) {
                        gVar.k(false);
                        break;
                    }
                }
                break;
            case 1:
                EditSessionLoggingHelperState editSessionLoggingHelperState = dVar.m.a;
                long id = ((DBStudySet) obj).getId();
                boolean z = dVar.F;
                int i4 = EditSetDetailsActivity.y;
                Intent intent = new Intent(dVar, (Class<?>) EditSetDetailsActivity.class);
                intent.putExtra("editSetActivityId", id);
                intent.putExtra("autoSuggest", z);
                intent.putExtra("editSessionTrackerKey", editSessionLoggingHelperState);
                com.quizlet.quizletandroid.sessionhelpers.a aVar = dVar.m;
                aVar.g();
                aVar.a.f = new SavedAction("tab_info", null, null);
                aVar.a.e = new Date();
                dVar.startActivityForResult(intent, 2000);
                break;
            case 2:
                dVar.y((io.reactivex.rxjava3.disposables.b) obj);
                break;
            default:
                com.quizlet.quizletandroid.ui.setcreation.managers.i iVar2 = dVar.y;
                if (iVar2.l) {
                    dVar.setTitle(R.string.edit_set_copy_title);
                } else if (iVar2.s) {
                    dVar.setTitle(R.string.edit_set_create_title);
                } else {
                    dVar.setTitle(R.string.edit_set_edit_title);
                }
                DBStudySet dBStudySet = dVar.y.m;
                AbstractC3107b6.h(((C4600d) dVar.k).d, dVar.l, new com.quizlet.login.magiclink.ui.e(dVar, 21), R.string.edit_set_offline_dialog_title, (dBStudySet == null || dBStudySet.getId() < 0) ? R.string.edit_set_offline_dialog_save_description : R.string.edit_set_offline_dialog_edit_description);
                break;
        }
    }
}
