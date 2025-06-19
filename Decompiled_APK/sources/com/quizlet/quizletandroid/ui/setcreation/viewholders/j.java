package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.wrappers.RawJsonObject;
import com.quizlet.quizletandroid.ui.common.widgets.QRichFormField;
import com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j implements TextWatcher {
    public int a;
    public final /* synthetic */ l b;

    public j(l lVar) {
        this.b = lVar;
    }

    @Override // android.text.TextWatcher
    public final void afterTextChanged(Editable s) {
        Intrinsics.checkNotNullParameter(s, "s");
        boolean z = false;
        boolean z2 = this.a > s.length();
        l lVar = this.b;
        String str = lVar.d;
        boolean z3 = str != null && z2;
        if (str != null && !z2) {
            z = true;
        }
        QRichFormField qRichFormField = lVar.f;
        String strValueOf = String.valueOf(qRichFormField != null ? qRichFormField.getText() : null);
        QRichFormField qRichFormField2 = lVar.f;
        String richTextJson = qRichFormField2 != null ? qRichFormField2.getRichTextJson() : null;
        if (richTextJson == null) {
            richTextJson = "";
        }
        if (lVar.a.equals(strValueOf) && lVar.b.equals(richTextJson)) {
            return;
        }
        if (z3) {
            Looper looperMyLooper = Looper.myLooper();
            if (looperMyLooper == null) {
                looperMyLooper = Looper.getMainLooper();
            }
            new Handler(looperMyLooper).post(new com.google.firebase.crashlytics.internal.common.i(26, lVar, str));
            if (str == null) {
                str = "";
            }
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            lVar.a = str;
            Intrinsics.checkNotNullParameter("", "<set-?>");
            lVar.b = "";
        } else {
            Intrinsics.checkNotNullParameter(strValueOf, "<set-?>");
            lVar.a = strValueOf;
            Intrinsics.checkNotNullParameter(richTextJson, "<set-?>");
            lVar.b = richTextJson;
        }
        m mVar = lVar.k;
        com.quizlet.quizletandroid.ui.setcreation.adapters.f fVar = mVar.i;
        int adapterPosition = mVar.getAdapterPosition();
        String str2 = lVar.a;
        QRichFormField qRichFormField3 = lVar.f;
        String richTextJson2 = qRichFormField3 != null ? qRichFormField3.getRichTextJson() : null;
        DBTerm dBTermJ = fVar.j(adapterPosition);
        if (dBTermJ != null) {
            boolean z4 = lVar.c;
            if (z4) {
                dBTermJ.setWord(str2);
                dBTermJ.setWordRichText(new RawJsonObject(richTextJson2));
            } else {
                dBTermJ.setDefinition(str2);
                dBTermJ.setDefinitionRichText(new RawJsonObject(richTextJson2));
            }
            com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a aVar = (com.quizlet.quizletandroid.ui.setcreation.activities.interfaces.a) fVar.r.get();
            if (aVar != null) {
                com.quizlet.quizletandroid.ui.setcreation.activities.a aVar2 = com.quizlet.quizletandroid.ui.setcreation.activities.a.a;
                com.quizlet.quizletandroid.ui.setcreation.activities.a aVar3 = com.quizlet.quizletandroid.ui.setcreation.activities.a.b;
                com.quizlet.quizletandroid.ui.setcreation.activities.a aVar4 = z4 ? aVar3 : aVar2;
                if (!z4) {
                    aVar2 = aVar3;
                }
                ((EditSetFragment) aVar).f0(dBTermJ, aVar4, aVar2);
            }
        }
        if (z) {
            lVar.b();
        }
    }

    @Override // android.text.TextWatcher
    public final void beforeTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
        this.a = s.length();
    }

    @Override // android.text.TextWatcher
    public final void onTextChanged(CharSequence s, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(s, "s");
    }
}
