package com.quizlet.quizletandroid.ui.setcreation.fragments;

import com.quizlet.features.setpage.terms.RefreshTermAndSelectedTermException;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ g(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                boolean zBooleanValue = ((Boolean) obj).booleanValue();
                EditSetFragment editSetFragment = (EditSetFragment) this.c;
                if (!zBooleanValue) {
                    String string = editSetFragment.getString(R.string.image_deletion_warning_dialog_title);
                    String string2 = editSetFragment.getString(R.string.image_deletion_warning_dialog_message);
                    Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                    String string3 = editSetFragment.getString(R.string.image_deletion_warning_dialog_ok_button);
                    Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                    String string4 = editSetFragment.getString(R.string.image_deletion_warning_dialog_cancel_button);
                    Intrinsics.checkNotNullExpressionValue(string4, "getString(...)");
                    EditSetFragment.U(editSetFragment, string, string2, string3, string4, this.b);
                    break;
                } else {
                    String string5 = editSetFragment.getString(R.string.image_deletion_warning_dialog_title);
                    String string6 = editSetFragment.getString(R.string.image_deletion_plus_user_warning_dialog_message);
                    Intrinsics.checkNotNullExpressionValue(string6, "getString(...)");
                    String string7 = editSetFragment.getString(R.string.image_deletion_warning_dialog_ok_button);
                    Intrinsics.checkNotNullExpressionValue(string7, "getString(...)");
                    String string8 = editSetFragment.getString(R.string.image_deletion_warning_dialog_cancel_button);
                    Intrinsics.checkNotNullExpressionValue(string8, "getString(...)");
                    EditSetFragment.U(editSetFragment, string5, string6, string7, string8, this.b);
                    break;
                }
            default:
                com.quizlet.infra.legacysyncengine.net.request.c it2 = (com.quizlet.infra.legacysyncengine.net.request.c) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (it2.b()) {
                    com.quizlet.data.repository.explanations.textbook.a aVar = (com.quizlet.data.repository.explanations.textbook.a) this.c;
                    io.reactivex.rxjava3.subjects.d dVar = (io.reactivex.rxjava3.subjects.d) aVar.c;
                    if (dVar != null) {
                        dVar.onError(new RefreshTermAndSelectedTermException(it2.a().a));
                    }
                    ((com.quizlet.infra.legacysyncengine.datasources.factory.b) aVar.a).a(this.b).a((com.quizlet.infra.legacysyncengine.datasources.factory.a) aVar.d);
                    io.reactivex.rxjava3.subjects.d dVar2 = (io.reactivex.rxjava3.subjects.d) aVar.c;
                    if (dVar2 != null) {
                        dVar2.onComplete();
                    }
                    aVar.c = null;
                    break;
                }
                break;
        }
    }
}
