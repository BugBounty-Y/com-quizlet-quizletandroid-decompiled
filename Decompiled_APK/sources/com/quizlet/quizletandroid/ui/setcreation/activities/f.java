package com.quizlet.quizletandroid.ui.setcreation.activities;

import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4601e;
import java.util.List;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;

    public /* synthetic */ f(h hVar, int i) {
        this.a = i;
        this.b = hVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                this.b.x((io.reactivex.rxjava3.disposables.b) obj);
                break;
            case 1:
                DBStudySet dBStudySet = (DBStudySet) obj;
                h hVar = this.b;
                hVar.r = dBStudySet;
                if (dBStudySet != null) {
                    C4601e c4601e = (C4601e) hVar.k;
                    QTextView qTextView = c4601e.g;
                    String strD = hVar.n.d(dBStudySet.getWordLang());
                    if (org.apache.commons.lang3.e.b(strD)) {
                        qTextView.setText(R.string.edit_set_language_placeholder_text);
                    } else {
                        c4601e.l.setText(strD);
                    }
                    String strD2 = hVar.n.d(hVar.r.getDefLang());
                    if (org.apache.commons.lang3.e.b(strD2)) {
                        qTextView.setText(R.string.edit_set_language_placeholder_text);
                    } else {
                        qTextView.setText(strD2);
                    }
                    hVar.O(dBStudySet);
                    break;
                }
                break;
            case 2:
                this.b.x((io.reactivex.rxjava3.disposables.b) obj);
                break;
            case 3:
                this.b.x((io.reactivex.rxjava3.disposables.b) obj);
                break;
            case 4:
                this.b.x((io.reactivex.rxjava3.disposables.b) obj);
                break;
            case 5:
                h hVar2 = this.b;
                hVar2.getClass();
                ((C4601e) hVar2.k).m.setVisibility(!((Boolean) obj).booleanValue() ? 0 : 8);
                break;
            case 6:
                this.b.x((io.reactivex.rxjava3.disposables.b) obj);
                break;
            default:
                this.b.s = (List) obj;
                break;
        }
    }
}
